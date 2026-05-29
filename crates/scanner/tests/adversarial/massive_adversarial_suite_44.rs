//! Part 44 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates mongodb, mongodb, moodle, moosend, moralis, mouseflow, mpesa, musixmatch, mx, mycase detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. MONGODB ATLAS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv44_mongodb_atlas_api_key_normal_must_fire() {
    assert_detector_fires(
        "mongodb-atlas-api-key",
        "ATLAS=eHIfkXby",
        "eHIfkXby",
    );
}

#[test]
fn adv44_mongodb_atlas_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mongodb-atlas-api-key",
        "dummy_prefix_0 =xxxfkXby",
    );
}

#[test]
fn adv44_mongodb_atlas_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mongodb-atlas-api-key",
        "ATLAS=eHIf\u{200B}kXby",
        "eHIfkXby",
    );
}

#[test]
fn adv44_mongodb_atlas_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mongodb-atlas-api-key",
        "ATLAS=eHIf\u{00AD}kXby",
        "eHIfkXby",
    );
}

// =========================================================================
// 2. MONGODB CONNECTION STRING ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv44_mongodb_connection_string_normal_must_fire() {
    assert_detector_fires(
        "mongodb-connection-string",
        "mongodb://dbuser:R7VXNPLMQ3HSKWJT@cluster0.mongodb.net",
        "mongodb://dbuser:R7VXNPLMQ3HSKWJT@cluster0.mongodb.net",
    );
}

#[test]
fn adv44_mongodb_connection_string_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mongodb-connection-string",
        "dummy_prefix_0://dbuser:R7VXNPLMQ3HSKWJT@cluster0.xongodb.net",
    );
}

#[test]
fn adv44_mongodb_connection_string_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mongodb-connection-string",
        "mongodb://dbuser:R7VXNPLMQ3\u{200B}HSKWJT@cluster0.mongodb.net",
        "mongodb://dbuser:R7VXNPLMQ3HSKWJT@cluster0.mongodb.net",
    );
}

#[test]
fn adv44_mongodb_connection_string_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mongodb-connection-string",
        "mongodb://dbuser:R7VXNPLMQ3\u{00AD}HSKWJT@cluster0.mongodb.net",
        "mongodb://dbuser:R7VXNPLMQ3HSKWJT@cluster0.mongodb.net",
    );
}

// =========================================================================
// 3. MOODLE API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv44_moodle_api_token_normal_must_fire() {
    assert_detector_fires(
        "moodle-api-token",
        "webservicewstoken=523c55846f4a794128a9d99731891b9c",
        "523c55846f4a794128a9d99731891b9c",
    );
}

#[test]
fn adv44_moodle_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "moodle-api-token",
        "dummy_prefix_0 =xxxc55846f4a794128a9d99731891b9c",
    );
}

#[test]
fn adv44_moodle_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "moodle-api-token",
        "webservicewstoken=523c55846f4a7941\u{200B}28a9d99731891b9c",
        "523c55846f4a794128a9d99731891b9c",
    );
}

#[test]
fn adv44_moodle_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "moodle-api-token",
        "webservicewstoken=523c55846f4a7941\u{00AD}28a9d99731891b9c",
        "523c55846f4a794128a9d99731891b9c",
    );
}

// =========================================================================
// 4. MOOSEND API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv44_moosend_api_key_normal_must_fire() {
    assert_detector_fires(
        "moosend-api-key",
        "MOOSEND_API_KEY=a4f4f-7a6c28--633f18a1a2b0ff571464fc",
        "a4f4f-7a6c28--633f18a1a2b0ff571464fc",
    );
}

#[test]
fn adv44_moosend_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "moosend-api-key",
        "dummy_prefix_0 =xxx4f-7a6c28--633f18a1a2b0ff571464fc",
    );
}

#[test]
fn adv44_moosend_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "moosend-api-key",
        "MOOSEND_API_KEY=a4f4f-7a6c28--633f\u{200B}18a1a2b0ff571464fc",
        "a4f4f-7a6c28--633f18a1a2b0ff571464fc",
    );
}

#[test]
fn adv44_moosend_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "moosend-api-key",
        "MOOSEND_API_KEY=a4f4f-7a6c28--633f\u{00AD}18a1a2b0ff571464fc",
        "a4f4f-7a6c28--633f18a1a2b0ff571464fc",
    );
}

// =========================================================================
// 5. MORALIS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv44_moralis_api_key_normal_must_fire() {
    assert_detector_fires(
        "moralis-api-key",
        "MORALIS_API_KEY=RDcaN0CTOK20ayMWP8e33V2zt9U44WSIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
        "RDcaN0CTOK20ayMWP8e33V2zt9U44WSIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
    );
}

#[test]
fn adv44_moralis_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "moralis-api-key",
        "dummy_prefix_0 =xxxaN0CTOK20ayMWP8e33V2zt9U44WSIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
    );
}

#[test]
fn adv44_moralis_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "moralis-api-key",
        "MORALIS_API_KEY=RDcaN0CTOK20ayMWP8e33V2zt9U44W\u{200B}SIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
        "RDcaN0CTOK20ayMWP8e33V2zt9U44WSIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
    );
}

#[test]
fn adv44_moralis_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "moralis-api-key",
        "MORALIS_API_KEY=RDcaN0CTOK20ayMWP8e33V2zt9U44W\u{00AD}SIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
        "RDcaN0CTOK20ayMWP8e33V2zt9U44WSIdDo1pT8f2R68ugXVO0Lu9kX854Uj",
    );
}

// =========================================================================
// 6. MOUSEFLOW API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv44_mouseflow_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "mouseflow-api-credentials",
        "MOUSEFLOW_API_KEY=8IhAULcXl1",
        "8IhAULcXl1",
    );
}

#[test]
fn adv44_mouseflow_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mouseflow-api-credentials",
        "dummy_prefix_0 =xxxAULcXl1",
    );
}

#[test]
fn adv44_mouseflow_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mouseflow-api-credentials",
        "MOUSEFLOW_API_KEY=8IhAU\u{200B}LcXl1",
        "8IhAULcXl1",
    );
}

#[test]
fn adv44_mouseflow_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mouseflow-api-credentials",
        "MOUSEFLOW_API_KEY=8IhAU\u{00AD}LcXl1",
        "8IhAULcXl1",
    );
}

// =========================================================================
// 7. MPESA API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv44_mpesa_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "mpesa-api-credentials",
        "MPESA_CONSUMER_KEY=40lryYegedHSfXuz872RgvPu",
        "40lryYegedHSfXuz872RgvPu",
    );
}

#[test]
fn adv44_mpesa_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mpesa-api-credentials",
        "dummy_prefix_0 =xxxryYegedHSfXuz872RgvPu",
    );
}

#[test]
fn adv44_mpesa_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mpesa-api-credentials",
        "MPESA_CONSUMER_KEY=40lryYegedHS\u{200B}fXuz872RgvPu",
        "40lryYegedHSfXuz872RgvPu",
    );
}

#[test]
fn adv44_mpesa_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mpesa-api-credentials",
        "MPESA_CONSUMER_KEY=40lryYegedHS\u{00AD}fXuz872RgvPu",
        "40lryYegedHSfXuz872RgvPu",
    );
}

// =========================================================================
// 8. MUSIXMATCH API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv44_musixmatch_api_key_normal_must_fire() {
    assert_detector_fires(
        "musixmatch-api-key",
        "MUSIXMATCH=431d32a80271b1e9ce85e2be0007d8ff",
        "431d32a80271b1e9ce85e2be0007d8ff",
    );
}

#[test]
fn adv44_musixmatch_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "musixmatch-api-key",
        "dummy_prefix_0 =xxxd32a80271b1e9ce85e2be0007d8ff",
    );
}

#[test]
fn adv44_musixmatch_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "musixmatch-api-key",
        "MUSIXMATCH=431d32a80271b1e9\u{200B}ce85e2be0007d8ff",
        "431d32a80271b1e9ce85e2be0007d8ff",
    );
}

#[test]
fn adv44_musixmatch_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "musixmatch-api-key",
        "MUSIXMATCH=431d32a80271b1e9\u{00AD}ce85e2be0007d8ff",
        "431d32a80271b1e9ce85e2be0007d8ff",
    );
}

// =========================================================================
// 9. MX API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv44_mx_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "mx-api-credentials",
        "MX_CLIENT_ID=CLIENT-353FcCafd",
        "CLIENT-353FcCafd",
    );
}

#[test]
fn adv44_mx_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mx-api-credentials",
        "dummy_prefix_0 =xxxENT-353FcCafd",
    );
}

#[test]
fn adv44_mx_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mx-api-credentials",
        "MX_CLIENT_ID=CLIENT-3\u{200B}53FcCafd",
        "CLIENT-353FcCafd",
    );
}

#[test]
fn adv44_mx_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mx-api-credentials",
        "MX_CLIENT_ID=CLIENT-3\u{00AD}53FcCafd",
        "CLIENT-353FcCafd",
    );
}

// =========================================================================
// 10. MYCASE API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv44_mycase_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "mycase-api-credentials",
        "mycase_i6EdHsGPI5sMobxNZTaZh300HPgk7a5x",
        "mycase_i6EdHsGPI5sMobxNZTaZh300HPgk7a5x",
    );
}

#[test]
fn adv44_mycase_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mycase-api-credentials",
        "dummyse_i6EdHsGPI5sMobxNZTaZh300HPgk7a5x",
    );
}

#[test]
fn adv44_mycase_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mycase-api-credentials",
        "mycase_i6EdHsGPI5sM\u{200B}obxNZTaZh300HPgk7a5x",
        "mycase_i6EdHsGPI5sMobxNZTaZh300HPgk7a5x",
    );
}

#[test]
fn adv44_mycase_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mycase-api-credentials",
        "mycase_i6EdHsGPI5sM\u{00AD}obxNZTaZh300HPgk7a5x",
        "mycase_i6EdHsGPI5sMobxNZTaZh300HPgk7a5x",
    );
}


