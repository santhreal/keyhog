//! Part 108 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates moralis, mouseflow, mpesa, musixmatch, mx, mycase, mysql, n8n, n8n, namely detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. MORALIS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv108_moralis_api_key_normal_must_fire() {
    assert_detector_fires(
        "moralis-api-key",
        "MORALIS_API_KEY=RDcaN0CTOK20ayMWP8e33V2zt9U44WSIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
        "RDcaN0CTOK20ayMWP8e33V2zt9U44WSIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
    );
}

#[test]
fn adv108_moralis_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "moralis-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv108_moralis_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "moralis-api-key",
        "MORALIS_API_KEY=RDcaN0CTOK20ayMWP8e33V2zt9U44W\u{200B}SIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
        "RDcaN0CTOK20ayMWP8e33V2zt9U44WSIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
    );
}

#[test]
fn adv108_moralis_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "moralis-api-key",
        "MORALIS_API_KEY=RDcaN0CTOK20ayMWP8e33V2zt9U44W\u{00AD}SIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
        "RDcaN0CTOK20ayMWP8e33V2zt9U44WSIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
    );
}

#[test]
fn adv108_moralis_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "moralis-api-key",
        "MORALIS_API_KEY=RDcaN0CTOK20ayMWP8e33V2zt9U44W\u{200C}SIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
        "RDcaN0CTOK20ayMWP8e33V2zt9U44WSIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
    );
}

#[test]
fn adv108_moralis_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "moralis-api-key",
        "MORALIS_API_KEY=RDcaN0CTOK20ayMWP8e33V2zt9U44W\u{200D}SIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
        "RDcaN0CTOK20ayMWP8e33V2zt9U44WSIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
    );
}

#[test]
fn adv108_moralis_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "moralis-api-key",
        "MORALIS_API_KEY=RDcaN0CTOK20ayMWP8e33V2zt9U44W\u{FEFF}SIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
        "RDcaN0CTOK20ayMWP8e33V2zt9U44WSIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
    );
}

#[test]
fn adv108_moralis_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "moralis-api-key",
        "MORALIS_API_KEY=RDcaN0CTOK20ayMWP8e33V2zt9U44W\u{2060}SIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
        "RDcaN0CTOK20ayMWP8e33V2zt9U44WSIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
    );
}

#[test]
fn adv108_moralis_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "moralis-api-key",
        "MORALIS_API_KEY=RDcaN0CTOK20ayMWP8e33V2zt9U44W\u{180E}SIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
        "RDcaN0CTOK20ayMWP8e33V2zt9U44WSIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
    );
}

#[test]
fn adv108_moralis_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "moralis-api-key",
        "MORALIS_API_KEY=RDcaN0CTOK20ayMWP8e33V2zt9U44W\u{202E}SIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
        "RDcaN0CTOK20ayMWP8e33V2zt9U44WSIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
    );
}

#[test]
fn adv108_moralis_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "moralis-api-key",
        "MORALIS_API_KEY=RDcaN0CTOK20ayMWP8e33V2zt9U44W\u{202C}SIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
        "RDcaN0CTOK20ayMWP8e33V2zt9U44WSIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
    );
}

#[test]
fn adv108_moralis_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "moralis-api-key",
        "MORALIS_API_KEY=RDcaN0CTOK20ayMWP8e33V2zt9U44W\u{200E}SIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
        "RDcaN0CTOK20ayMWP8e33V2zt9U44WSIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
    );
}

// =========================================================================
// 2. MOUSEFLOW API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv108_mouseflow_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "mouseflow-api-credentials",
        "MOUSEFLOW_API_KEY=8IhAULcXl1",
        "8IhAULcXl1",
    );
}

#[test]
fn adv108_mouseflow_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent("mouseflow-api-credentials", "dummy_prefix_0 =xxxxxxxxxx");
}

#[test]
fn adv108_mouseflow_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mouseflow-api-credentials",
        "MOUSEFLOW_API_KEY=8IhAU\u{200B}LcXl1",
        "8IhAULcXl1",
    );
}

#[test]
fn adv108_mouseflow_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mouseflow-api-credentials",
        "MOUSEFLOW_API_KEY=8IhAU\u{00AD}LcXl1",
        "8IhAULcXl1",
    );
}

#[test]
fn adv108_mouseflow_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "mouseflow-api-credentials",
        "MOUSEFLOW_API_KEY=8IhAU\u{200C}LcXl1",
        "8IhAULcXl1",
    );
}

#[test]
fn adv108_mouseflow_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "mouseflow-api-credentials",
        "MOUSEFLOW_API_KEY=8IhAU\u{200D}LcXl1",
        "8IhAULcXl1",
    );
}

#[test]
fn adv108_mouseflow_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "mouseflow-api-credentials",
        "MOUSEFLOW_API_KEY=8IhAU\u{FEFF}LcXl1",
        "8IhAULcXl1",
    );
}

#[test]
fn adv108_mouseflow_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "mouseflow-api-credentials",
        "MOUSEFLOW_API_KEY=8IhAU\u{2060}LcXl1",
        "8IhAULcXl1",
    );
}

#[test]
fn adv108_mouseflow_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "mouseflow-api-credentials",
        "MOUSEFLOW_API_KEY=8IhAU\u{180E}LcXl1",
        "8IhAULcXl1",
    );
}

#[test]
fn adv108_mouseflow_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "mouseflow-api-credentials",
        "MOUSEFLOW_API_KEY=8IhAU\u{202E}LcXl1",
        "8IhAULcXl1",
    );
}

#[test]
fn adv108_mouseflow_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "mouseflow-api-credentials",
        "MOUSEFLOW_API_KEY=8IhAU\u{202C}LcXl1",
        "8IhAULcXl1",
    );
}

#[test]
fn adv108_mouseflow_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "mouseflow-api-credentials",
        "MOUSEFLOW_API_KEY=8IhAU\u{200E}LcXl1",
        "8IhAULcXl1",
    );
}

// =========================================================================
// 3. MPESA API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv108_mpesa_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "mpesa-api-credentials",
        "MPESA_CONSUMER_KEY=40lryYegedHSfXuz872RgvPu",
        "40lryYegedHSfXuz872RgvPu",
    );
}

#[test]
fn adv108_mpesa_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mpesa-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv108_mpesa_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mpesa-api-credentials",
        "MPESA_CONSUMER_KEY=40lryYegedHS\u{200B}fXuz872RgvPu",
        "40lryYegedHSfXuz872RgvPu",
    );
}

#[test]
fn adv108_mpesa_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mpesa-api-credentials",
        "MPESA_CONSUMER_KEY=40lryYegedHS\u{00AD}fXuz872RgvPu",
        "40lryYegedHSfXuz872RgvPu",
    );
}

#[test]
fn adv108_mpesa_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "mpesa-api-credentials",
        "MPESA_CONSUMER_KEY=40lryYegedHS\u{200C}fXuz872RgvPu",
        "40lryYegedHSfXuz872RgvPu",
    );
}

#[test]
fn adv108_mpesa_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "mpesa-api-credentials",
        "MPESA_CONSUMER_KEY=40lryYegedHS\u{200D}fXuz872RgvPu",
        "40lryYegedHSfXuz872RgvPu",
    );
}

#[test]
fn adv108_mpesa_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "mpesa-api-credentials",
        "MPESA_CONSUMER_KEY=40lryYegedHS\u{FEFF}fXuz872RgvPu",
        "40lryYegedHSfXuz872RgvPu",
    );
}

#[test]
fn adv108_mpesa_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "mpesa-api-credentials",
        "MPESA_CONSUMER_KEY=40lryYegedHS\u{2060}fXuz872RgvPu",
        "40lryYegedHSfXuz872RgvPu",
    );
}

#[test]
fn adv108_mpesa_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "mpesa-api-credentials",
        "MPESA_CONSUMER_KEY=40lryYegedHS\u{180E}fXuz872RgvPu",
        "40lryYegedHSfXuz872RgvPu",
    );
}

#[test]
fn adv108_mpesa_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "mpesa-api-credentials",
        "MPESA_CONSUMER_KEY=40lryYegedHS\u{202E}fXuz872RgvPu",
        "40lryYegedHSfXuz872RgvPu",
    );
}

#[test]
fn adv108_mpesa_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "mpesa-api-credentials",
        "MPESA_CONSUMER_KEY=40lryYegedHS\u{202C}fXuz872RgvPu",
        "40lryYegedHSfXuz872RgvPu",
    );
}

#[test]
fn adv108_mpesa_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "mpesa-api-credentials",
        "MPESA_CONSUMER_KEY=40lryYegedHS\u{200E}fXuz872RgvPu",
        "40lryYegedHSfXuz872RgvPu",
    );
}

// =========================================================================
// 4. MUSIXMATCH API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv108_musixmatch_api_key_normal_must_fire() {
    assert_detector_fires(
        "musixmatch-api-key",
        "MUSIXMATCH=431d32a80271b1e9ce85e2be0007d8ff",
        "431d32a80271b1e9ce85e2be0007d8ff",
    );
}

#[test]
fn adv108_musixmatch_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "musixmatch-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv108_musixmatch_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "musixmatch-api-key",
        "MUSIXMATCH=431d32a80271b1e9\u{200B}ce85e2be0007d8ff",
        "431d32a80271b1e9ce85e2be0007d8ff",
    );
}

#[test]
fn adv108_musixmatch_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "musixmatch-api-key",
        "MUSIXMATCH=431d32a80271b1e9\u{00AD}ce85e2be0007d8ff",
        "431d32a80271b1e9ce85e2be0007d8ff",
    );
}

#[test]
fn adv108_musixmatch_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "musixmatch-api-key",
        "MUSIXMATCH=431d32a80271b1e9\u{200C}ce85e2be0007d8ff",
        "431d32a80271b1e9ce85e2be0007d8ff",
    );
}

#[test]
fn adv108_musixmatch_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "musixmatch-api-key",
        "MUSIXMATCH=431d32a80271b1e9\u{200D}ce85e2be0007d8ff",
        "431d32a80271b1e9ce85e2be0007d8ff",
    );
}

#[test]
fn adv108_musixmatch_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "musixmatch-api-key",
        "MUSIXMATCH=431d32a80271b1e9\u{FEFF}ce85e2be0007d8ff",
        "431d32a80271b1e9ce85e2be0007d8ff",
    );
}

#[test]
fn adv108_musixmatch_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "musixmatch-api-key",
        "MUSIXMATCH=431d32a80271b1e9\u{2060}ce85e2be0007d8ff",
        "431d32a80271b1e9ce85e2be0007d8ff",
    );
}

#[test]
fn adv108_musixmatch_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "musixmatch-api-key",
        "MUSIXMATCH=431d32a80271b1e9\u{180E}ce85e2be0007d8ff",
        "431d32a80271b1e9ce85e2be0007d8ff",
    );
}

#[test]
fn adv108_musixmatch_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "musixmatch-api-key",
        "MUSIXMATCH=431d32a80271b1e9\u{202E}ce85e2be0007d8ff",
        "431d32a80271b1e9ce85e2be0007d8ff",
    );
}

#[test]
fn adv108_musixmatch_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "musixmatch-api-key",
        "MUSIXMATCH=431d32a80271b1e9\u{202C}ce85e2be0007d8ff",
        "431d32a80271b1e9ce85e2be0007d8ff",
    );
}

#[test]
fn adv108_musixmatch_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "musixmatch-api-key",
        "MUSIXMATCH=431d32a80271b1e9\u{200E}ce85e2be0007d8ff",
        "431d32a80271b1e9ce85e2be0007d8ff",
    );
}

// =========================================================================
// 5. MX API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv108_mx_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "mx-api-credentials",
        "MX_CLIENT_ID=CLIENT-353FcCafd",
        "CLIENT-353FcCafd",
    );
}

#[test]
fn adv108_mx_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent("mx-api-credentials", "dummy_prefix_0 =xxxxxxxxxxxxxxxx");
}

#[test]
fn adv108_mx_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mx-api-credentials",
        "MX_CLIENT_ID=CLIENT-3\u{200B}53FcCafd",
        "CLIENT-353FcCafd",
    );
}

#[test]
fn adv108_mx_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mx-api-credentials",
        "MX_CLIENT_ID=CLIENT-3\u{00AD}53FcCafd",
        "CLIENT-353FcCafd",
    );
}

#[test]
fn adv108_mx_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "mx-api-credentials",
        "MX_CLIENT_ID=CLIENT-3\u{200C}53FcCafd",
        "CLIENT-353FcCafd",
    );
}

#[test]
fn adv108_mx_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "mx-api-credentials",
        "MX_CLIENT_ID=CLIENT-3\u{200D}53FcCafd",
        "CLIENT-353FcCafd",
    );
}

#[test]
fn adv108_mx_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "mx-api-credentials",
        "MX_CLIENT_ID=CLIENT-3\u{FEFF}53FcCafd",
        "CLIENT-353FcCafd",
    );
}

#[test]
fn adv108_mx_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "mx-api-credentials",
        "MX_CLIENT_ID=CLIENT-3\u{2060}53FcCafd",
        "CLIENT-353FcCafd",
    );
}

#[test]
fn adv108_mx_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "mx-api-credentials",
        "MX_CLIENT_ID=CLIENT-3\u{180E}53FcCafd",
        "CLIENT-353FcCafd",
    );
}

#[test]
fn adv108_mx_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "mx-api-credentials",
        "MX_CLIENT_ID=CLIENT-3\u{202E}53FcCafd",
        "CLIENT-353FcCafd",
    );
}

#[test]
fn adv108_mx_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "mx-api-credentials",
        "MX_CLIENT_ID=CLIENT-3\u{202C}53FcCafd",
        "CLIENT-353FcCafd",
    );
}

#[test]
fn adv108_mx_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "mx-api-credentials",
        "MX_CLIENT_ID=CLIENT-3\u{200E}53FcCafd",
        "CLIENT-353FcCafd",
    );
}

// =========================================================================
// 6. MYCASE API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv108_mycase_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "mycase-api-credentials",
        "mycase_i6EdHsGPI5sMobxNZTaZh300HPgk7a5x",
        "mycase_i6EdHsGPI5sMobxNZTaZh300HPgk7a5x",
    );
}

#[test]
fn adv108_mycase_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mycase-api-credentials",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv108_mycase_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mycase-api-credentials",
        "mycase_i6EdHsGPI5sM\u{200B}obxNZTaZh300HPgk7a5x",
        "mycase_i6EdHsGPI5sMobxNZTaZh300HPgk7a5x",
    );
}

#[test]
fn adv108_mycase_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mycase-api-credentials",
        "mycase_i6EdHsGPI5sM\u{00AD}obxNZTaZh300HPgk7a5x",
        "mycase_i6EdHsGPI5sMobxNZTaZh300HPgk7a5x",
    );
}

#[test]
fn adv108_mycase_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "mycase-api-credentials",
        "mycase_i6EdHsGPI5sM\u{200C}obxNZTaZh300HPgk7a5x",
        "mycase_i6EdHsGPI5sMobxNZTaZh300HPgk7a5x",
    );
}

#[test]
fn adv108_mycase_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "mycase-api-credentials",
        "mycase_i6EdHsGPI5sM\u{200D}obxNZTaZh300HPgk7a5x",
        "mycase_i6EdHsGPI5sMobxNZTaZh300HPgk7a5x",
    );
}

#[test]
fn adv108_mycase_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "mycase-api-credentials",
        "mycase_i6EdHsGPI5sM\u{FEFF}obxNZTaZh300HPgk7a5x",
        "mycase_i6EdHsGPI5sMobxNZTaZh300HPgk7a5x",
    );
}

#[test]
fn adv108_mycase_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "mycase-api-credentials",
        "mycase_i6EdHsGPI5sM\u{2060}obxNZTaZh300HPgk7a5x",
        "mycase_i6EdHsGPI5sMobxNZTaZh300HPgk7a5x",
    );
}

#[test]
fn adv108_mycase_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "mycase-api-credentials",
        "mycase_i6EdHsGPI5sM\u{180E}obxNZTaZh300HPgk7a5x",
        "mycase_i6EdHsGPI5sMobxNZTaZh300HPgk7a5x",
    );
}

#[test]
fn adv108_mycase_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "mycase-api-credentials",
        "mycase_i6EdHsGPI5sM\u{202E}obxNZTaZh300HPgk7a5x",
        "mycase_i6EdHsGPI5sMobxNZTaZh300HPgk7a5x",
    );
}

#[test]
fn adv108_mycase_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "mycase-api-credentials",
        "mycase_i6EdHsGPI5sM\u{202C}obxNZTaZh300HPgk7a5x",
        "mycase_i6EdHsGPI5sMobxNZTaZh300HPgk7a5x",
    );
}

#[test]
fn adv108_mycase_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "mycase-api-credentials",
        "mycase_i6EdHsGPI5sM\u{200E}obxNZTaZh300HPgk7a5x",
        "mycase_i6EdHsGPI5sMobxNZTaZh300HPgk7a5x",
    );
}

// =========================================================================
// 7. MYSQL CONNECTION STRING ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv108_mysql_connection_string_normal_must_fire() {
    assert_detector_fires(
        "mysql-connection-string",
        "mysql://dbuser:Np3DnCDi231ZUBYp@prod-db.example.com",
        "mysql://dbuser:Np3DnCDi231ZUBYp@prod-db.example.com",
    );
}

#[test]
fn adv108_mysql_connection_string_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mysql-connection-string",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv108_mysql_connection_string_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mysql-connection-string",
        "mysql://dbuser:Np3DnCDi23\u{200B}1ZUBYp@prod-db.example.com",
        "mysql://dbuser:Np3DnCDi231ZUBYp@prod-db.example.com",
    );
}

#[test]
fn adv108_mysql_connection_string_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mysql-connection-string",
        "mysql://dbuser:Np3DnCDi23\u{00AD}1ZUBYp@prod-db.example.com",
        "mysql://dbuser:Np3DnCDi231ZUBYp@prod-db.example.com",
    );
}

#[test]
fn adv108_mysql_connection_string_evade_zwnj_must_fire() {
    assert_detector_fires(
        "mysql-connection-string",
        "mysql://dbuser:Np3DnCDi23\u{200C}1ZUBYp@prod-db.example.com",
        "mysql://dbuser:Np3DnCDi231ZUBYp@prod-db.example.com",
    );
}

#[test]
fn adv108_mysql_connection_string_evade_zwj_must_fire() {
    assert_detector_fires(
        "mysql-connection-string",
        "mysql://dbuser:Np3DnCDi23\u{200D}1ZUBYp@prod-db.example.com",
        "mysql://dbuser:Np3DnCDi231ZUBYp@prod-db.example.com",
    );
}

#[test]
fn adv108_mysql_connection_string_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "mysql-connection-string",
        "mysql://dbuser:Np3DnCDi23\u{FEFF}1ZUBYp@prod-db.example.com",
        "mysql://dbuser:Np3DnCDi231ZUBYp@prod-db.example.com",
    );
}

#[test]
fn adv108_mysql_connection_string_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "mysql-connection-string",
        "mysql://dbuser:Np3DnCDi23\u{2060}1ZUBYp@prod-db.example.com",
        "mysql://dbuser:Np3DnCDi231ZUBYp@prod-db.example.com",
    );
}

#[test]
fn adv108_mysql_connection_string_evade_mongolian_must_fire() {
    assert_detector_fires(
        "mysql-connection-string",
        "mysql://dbuser:Np3DnCDi23\u{180E}1ZUBYp@prod-db.example.com",
        "mysql://dbuser:Np3DnCDi231ZUBYp@prod-db.example.com",
    );
}

#[test]
fn adv108_mysql_connection_string_evade_rtl_must_fire() {
    assert_detector_fires(
        "mysql-connection-string",
        "mysql://dbuser:Np3DnCDi23\u{202E}1ZUBYp@prod-db.example.com",
        "mysql://dbuser:Np3DnCDi231ZUBYp@prod-db.example.com",
    );
}

#[test]
fn adv108_mysql_connection_string_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "mysql-connection-string",
        "mysql://dbuser:Np3DnCDi23\u{202C}1ZUBYp@prod-db.example.com",
        "mysql://dbuser:Np3DnCDi231ZUBYp@prod-db.example.com",
    );
}

#[test]
fn adv108_mysql_connection_string_evade_lrm_must_fire() {
    assert_detector_fires(
        "mysql-connection-string",
        "mysql://dbuser:Np3DnCDi23\u{200E}1ZUBYp@prod-db.example.com",
        "mysql://dbuser:Np3DnCDi231ZUBYp@prod-db.example.com",
    );
}

// =========================================================================
// 8. N8N API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv108_n8n_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "n8n-api-credentials",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
    );
}

#[test]
fn adv108_n8n_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "n8n-api-credentials",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv108_n8n_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "n8n-api-credentials",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg\u{200B}9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
    );
}

#[test]
fn adv108_n8n_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "n8n-api-credentials",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg\u{00AD}9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
    );
}

#[test]
fn adv108_n8n_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "n8n-api-credentials",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg\u{200C}9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
    );
}

#[test]
fn adv108_n8n_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "n8n-api-credentials",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg\u{200D}9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
    );
}

#[test]
fn adv108_n8n_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "n8n-api-credentials",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg\u{FEFF}9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
    );
}

#[test]
fn adv108_n8n_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "n8n-api-credentials",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg\u{2060}9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
    );
}

#[test]
fn adv108_n8n_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "n8n-api-credentials",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg\u{180E}9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
    );
}

#[test]
fn adv108_n8n_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "n8n-api-credentials",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg\u{202E}9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
    );
}

#[test]
fn adv108_n8n_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "n8n-api-credentials",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg\u{202C}9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
    );
}

#[test]
fn adv108_n8n_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "n8n-api-credentials",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg\u{200E}9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
    );
}

// =========================================================================
// 9. N8N WEBHOOK CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv108_n8n_webhook_credentials_normal_must_fire() {
    assert_detector_fires(
        "n8n-webhook-credentials",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
    );
}

#[test]
fn adv108_n8n_webhook_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "n8n-webhook-credentials",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv108_n8n_webhook_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "n8n-webhook-credentials",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9\u{200B}d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
    );
}

#[test]
fn adv108_n8n_webhook_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "n8n-webhook-credentials",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9\u{00AD}d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
    );
}

#[test]
fn adv108_n8n_webhook_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "n8n-webhook-credentials",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9\u{200C}d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
    );
}

#[test]
fn adv108_n8n_webhook_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "n8n-webhook-credentials",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9\u{200D}d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
    );
}

#[test]
fn adv108_n8n_webhook_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "n8n-webhook-credentials",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9\u{FEFF}d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
    );
}

#[test]
fn adv108_n8n_webhook_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "n8n-webhook-credentials",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9\u{2060}d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
    );
}

#[test]
fn adv108_n8n_webhook_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "n8n-webhook-credentials",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9\u{180E}d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
    );
}

#[test]
fn adv108_n8n_webhook_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "n8n-webhook-credentials",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9\u{202E}d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
    );
}

#[test]
fn adv108_n8n_webhook_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "n8n-webhook-credentials",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9\u{202C}d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
    );
}

#[test]
fn adv108_n8n_webhook_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "n8n-webhook-credentials",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9\u{200E}d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
    );
}

// =========================================================================
// 10. NAMELY API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv108_namely_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "namely-api-credentials",
        "NAMELY_API_KEY=iLTnnJ2eXTQr7V8YOPWz",
        "iLTnnJ2eXTQr7V8YOPWz",
    );
}

#[test]
fn adv108_namely_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "namely-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv108_namely_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "namely-api-credentials",
        "NAMELY_API_KEY=iLTnnJ2eXT\u{200B}Qr7V8YOPWz",
        "iLTnnJ2eXTQr7V8YOPWz",
    );
}

#[test]
fn adv108_namely_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "namely-api-credentials",
        "NAMELY_API_KEY=iLTnnJ2eXT\u{00AD}Qr7V8YOPWz",
        "iLTnnJ2eXTQr7V8YOPWz",
    );
}

#[test]
fn adv108_namely_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "namely-api-credentials",
        "NAMELY_API_KEY=iLTnnJ2eXT\u{200C}Qr7V8YOPWz",
        "iLTnnJ2eXTQr7V8YOPWz",
    );
}

#[test]
fn adv108_namely_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "namely-api-credentials",
        "NAMELY_API_KEY=iLTnnJ2eXT\u{200D}Qr7V8YOPWz",
        "iLTnnJ2eXTQr7V8YOPWz",
    );
}

#[test]
fn adv108_namely_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "namely-api-credentials",
        "NAMELY_API_KEY=iLTnnJ2eXT\u{FEFF}Qr7V8YOPWz",
        "iLTnnJ2eXTQr7V8YOPWz",
    );
}

#[test]
fn adv108_namely_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "namely-api-credentials",
        "NAMELY_API_KEY=iLTnnJ2eXT\u{2060}Qr7V8YOPWz",
        "iLTnnJ2eXTQr7V8YOPWz",
    );
}

#[test]
fn adv108_namely_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "namely-api-credentials",
        "NAMELY_API_KEY=iLTnnJ2eXT\u{180E}Qr7V8YOPWz",
        "iLTnnJ2eXTQr7V8YOPWz",
    );
}

#[test]
fn adv108_namely_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "namely-api-credentials",
        "NAMELY_API_KEY=iLTnnJ2eXT\u{202E}Qr7V8YOPWz",
        "iLTnnJ2eXTQr7V8YOPWz",
    );
}

#[test]
fn adv108_namely_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "namely-api-credentials",
        "NAMELY_API_KEY=iLTnnJ2eXT\u{202C}Qr7V8YOPWz",
        "iLTnnJ2eXTQr7V8YOPWz",
    );
}

#[test]
fn adv108_namely_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "namely-api-credentials",
        "NAMELY_API_KEY=iLTnnJ2eXT\u{200E}Qr7V8YOPWz",
        "iLTnnJ2eXTQr7V8YOPWz",
    );
}
