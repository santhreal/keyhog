//! Part 13 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates Backblaze B2, Baidu Maps, BambooHR, Bandwidth, Base Chain,
//! Basecamp, Baseten, Belvo, Better Stack, and BigCommerce detectors against
//! zero-width spaces, soft hyphens, combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. BACKBLAZE B2 APPLICATION KEY (V2) ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv13_backblaze_normal_must_fire() {
    assert_detector_fires(
        "backblaze-b2-app-key-v2",
        "K00Mabcde1234567890abcde1",
        "K00Mabcde1234567890abcde1",
    );
}

#[test]
fn adv13_backblaze_wrong_prefix_must_silent() {
    assert_detector_silent("backblaze-b2-app-key-v2", "K00Oabcde1234567890abcde1");
}

#[test]
fn adv13_backblaze_evade_zwsp_must_fire() {
    assert_detector_fires(
        "backblaze-b2-app-key-v2",
        "K00M\u{200B}abcde1234567890abcde1",
        "K00Mabcde1234567890abcde1",
    );
}

#[test]
fn adv13_backblaze_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "backblaze-b2-app-key-v2",
        "K00Mabcde12345\u{00AD}67890abcde1",
        "K00Mabcde1234567890abcde1",
    );
}

#[test]
fn adv13_backblaze_evade_homoglyph_evaded_must_stay_silent() {
    assert_detector_silent("backblaze-b2-app-key-v2", "K\u{043E}\u{043E}Mabcde1234567890abcde1");
}

// =========================================================================
// 2. BAIDU MAPS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv13_baidu_normal_must_fire() {
    assert_detector_fires(
        "baidu-maps-api-key",
        "baidu_maps_key = \"abcde1234567890abcde1234\"",
        "abcde1234567890abcde1234",
    );
}

#[test]
fn adv13_baidu_wrong_prefix_must_silent() {
    assert_detector_silent(
        "baidu-maps-api-key",
        "google_maps_key = \"abcde1234567890abcde1234\"",
    );
}

#[test]
fn adv13_baidu_evade_zwsp_must_fire() {
    assert_detector_fires(
        "baidu-maps-api-key",
        "baidu\u{200B}_maps_key = \"abcde1234567890abcde1234\"",
        "abcde1234567890abcde1234",
    );
}

#[test]
fn adv13_baidu_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "baidu-maps-api-key",
        "baidu_maps_key = \"abcde12345\u{00AD}67890abcde1234\"",
        "abcde1234567890abcde1234",
    );
}

#[test]
fn adv13_baidu_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "baidu-maps-api-key",
        "ba\u{0457}du_maps_key = \"abcde1234567890abcde1234\"",
        "abcde1234567890abcde1234",
    );
}

// =========================================================================
// 3. BAMBOOHR API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv13_bamboohr_normal_must_fire() {
    assert_detector_fires(
        "bamboohr-api-key",
        "bamboohr_api_key = \"abcde1234567890abcde123456789012abcde123\"",
        "abcde1234567890abcde123456789012abcde123",
    );
}

#[test]
fn adv13_bamboohr_wrong_prefix_must_silent() {
    assert_detector_silent(
        "bamboohr-api-key",
        "bambooland_api_key = \"abcde1234567890abcde123456789012abcde123\"",
    );
}

#[test]
fn adv13_bamboohr_evade_zwsp_must_fire() {
    assert_detector_fires(
        "bamboohr-api-key",
        "bamboohr\u{200B}_api_key = \"abcde1234567890abcde123456789012abcde123\"",
        "abcde1234567890abcde123456789012abcde123",
    );
}

#[test]
fn adv13_bamboohr_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "bamboohr-api-key",
        "bamboohr_api_key = \"abcde1234567890abcde1\u{00AD}23456789012abcde123\"",
        "abcde1234567890abcde123456789012abcde123",
    );
}

#[test]
fn adv13_bamboohr_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "bamboohr-api-key",
        "bamb\u{043E}\u{043E}hr_api_key = \"abcde1234567890abcde123456789012abcde123\"",
        "abcde1234567890abcde123456789012abcde123",
    );
}

// =========================================================================
// 4. BANDWIDTH API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv13_bandwidth_normal_must_fire() {
    assert_detector_fires(
        "bandwidth-api-key",
        "bandwidth_api_token = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv13_bandwidth_wrong_prefix_must_silent() {
    assert_detector_silent(
        "bandwidth-api-key",
        "brandwidth_api_token = \"abcde1234567890abcde\"",
    );
}

#[test]
fn adv13_bandwidth_evade_zwsp_must_fire() {
    assert_detector_fires(
        "bandwidth-api-key",
        "bandwidth\u{200B}_api_token = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv13_bandwidth_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "bandwidth-api-key",
        "bandwidth_api_token = \"abcde12345\u{00AD}67890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv13_bandwidth_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "bandwidth-api-key",
        "bandw\u{0456}dth_api_token = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}

// =========================================================================
// 5. BASE CHAIN API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv13_base_normal_must_fire() {
    assert_detector_fires(
        "base-api-credentials",
        "base-api-key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv13_base_wrong_prefix_must_silent() {
    assert_detector_silent(
        "base-api-credentials",
        "acid-api-key = \"abcde1234567890abcde123456789012\"",
    );
}

#[test]
fn adv13_base_evade_zwsp_must_fire() {
    assert_detector_fires(
        "base-api-credentials",
        "base\u{200B}-api-key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv13_base_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "base-api-credentials",
        "base-api-key = \"abcde1234567890abcde1\u{00AD}23456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv13_base_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "base-api-credentials",
        "bas\u{0435}-api-key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

// =========================================================================
// 6. BASECAMP ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv13_basecamp_normal_must_fire() {
    assert_detector_fires(
        "basecamp-access-token",
        "BASECAMP_TOKEN = \"abcde1234567890abcde1234567890abcde12345\"",
        "abcde1234567890abcde1234567890abcde12345",
    );
}

#[test]
fn adv13_basecamp_wrong_prefix_must_silent() {
    assert_detector_silent(
        "basecamp-access-token",
        "VCS_TOKEN = \"abcde1234567890abcde1234567890abcde12345\"",
    );
}

#[test]
fn adv13_basecamp_evade_zwsp_must_fire() {
    assert_detector_fires(
        "basecamp-access-token",
        "BASECAMP\u{200B}_TOKEN = \"abcde1234567890abcde1234567890abcde12345\"",
        "abcde1234567890abcde1234567890abcde12345",
    );
}

#[test]
fn adv13_basecamp_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "basecamp-access-token",
        "BASECAMP_TOKEN = \"abcde1234567890abcde1\u{00AD}234567890abcde12345\"",
        "abcde1234567890abcde1234567890abcde12345",
    );
}

#[test]
fn adv13_basecamp_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "basecamp-access-token",
        "basec\u{0430}mp_token = \"abcde1234567890abcde1234567890abcde12345\"",
        "abcde1234567890abcde1234567890abcde12345",
    );
}

// =========================================================================
// 7. BASETEN API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv13_baseten_normal_must_fire() {
    assert_detector_fires(
        "baseten-api-key",
        "BASETEN_API_KEY = \"abcde1234567890abcde1234567890\"",
        "abcde1234567890abcde1234567890",
    );
}

#[test]
fn adv13_baseten_wrong_prefix_must_silent() {
    assert_detector_silent(
        "baseten-api-key",
        "BASETWENTY_API_KEY = \"abcde1234567890abcde1234567890\"",
    );
}

#[test]
fn adv13_baseten_evade_zwsp_must_fire() {
    assert_detector_fires(
        "baseten-api-key",
        "BASETEN\u{200B}_API_KEY = \"abcde1234567890abcde1234567890\"",
        "abcde1234567890abcde1234567890",
    );
}

#[test]
fn adv13_baseten_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "baseten-api-key",
        "BASETEN_API_KEY = \"abcde1234567890abcde1\u{00AD}234567890\"",
        "abcde1234567890abcde1234567890",
    );
}

#[test]
fn adv13_baseten_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "baseten-api-key",
        "bas\u{0435}ten_api_key = \"abcde1234567890abcde1234567890\"",
        "abcde1234567890abcde1234567890",
    );
}

// =========================================================================
// 8. BELVO API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv13_belvo_normal_must_fire() {
    assert_detector_fires(
        "belvo-api-credentials",
        "belvo_secret_id = \"12345678-abcd-1234-abcd-1234567890ab\"",
        "12345678-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv13_belvo_wrong_prefix_must_silent() {
    assert_detector_silent(
        "belvo-api-credentials",
        "pelvo_secret_id = \"12345678-abcd-1234-abcd-1234567890ab\"",
    );
}

#[test]
fn adv13_belvo_evade_zwsp_must_fire() {
    assert_detector_fires(
        "belvo-api-credentials",
        "belvo\u{200B}_secret_id = \"12345678-abcd-1234-abcd-1234567890ab\"",
        "12345678-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv13_belvo_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "belvo-api-credentials",
        "belvo_secret_id = \"12345678-abcd-1234-abcd-12345678\u{00AD}90ab\"",
        "12345678-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv13_belvo_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "belvo-api-credentials",
        "b\u{0435}lvo_secret_id = \"12345678-abcd-1234-abcd-1234567890ab\"",
        "12345678-abcd-1234-abcd-1234567890ab",
    );
}

// =========================================================================
// 9. BETTER STACK SOURCE TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv13_betterstack_normal_must_fire() {
    assert_detector_fires(
        "betterstack-source-token",
        "betterstack_token = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv13_betterstack_wrong_prefix_must_silent() {
    assert_detector_silent(
        "betterstack-source-token",
        "worsestack_token = \"abcde1234567890abcde123456789012\"",
    );
}

#[test]
fn adv13_betterstack_evade_zwsp_must_fire() {
    assert_detector_fires(
        "betterstack-source-token",
        "betterstack\u{200B}_token = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv13_betterstack_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "betterstack-source-token",
        "betterstack_token = \"abcde1234567890abcde1\u{00AD}23456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv13_betterstack_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "betterstack-source-token",
        "bett\u{0435}rstack_token = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

// =========================================================================
// 10. BIGCOMMERCE ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv13_bigcommerce_normal_must_fire() {
    assert_detector_fires(
        "bigcommerce-access-token",
        "bbc_abcde1234567890abcde1234567890abcde1234567890abcd",
        "bbc_abcde1234567890abcde1234567890abcde1234567890abcd",
    );
}

#[test]
fn adv13_bigcommerce_wrong_prefix_must_silent() {
    assert_detector_silent(
        "bigcommerce-access-token",
        "cbc_abcde1234567890abcde1234567890abcde1234567890abcd",
    );
}

#[test]
fn adv13_bigcommerce_evade_zwsp_must_fire() {
    assert_detector_fires(
        "bigcommerce-access-token",
        "bbc\u{200B}_abcde1234567890abcde1234567890abcde1234567890abcd",
        "bbc_abcde1234567890abcde1234567890abcde1234567890abcd",
    );
}

#[test]
fn adv13_bigcommerce_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "bigcommerce-access-token",
        "bbc_abcde1234567890abcde1\u{00AD}234567890abcde1234567890abcd",
        "bbc_abcde1234567890abcde1234567890abcde1234567890abcd",
    );
}

#[test]
fn adv13_bigcommerce_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "bigcommerce-access-token",
        "bbc_abcd\u{0435}1234567890abcde1234567890abcde1234567890abcd",
        "bbc_abcde1234567890abcde1234567890abcde1234567890abcd",
    );
}
