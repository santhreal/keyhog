//! Part 14 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates BigCommerce Store, Bing Maps, Bitbucket App Password, Bitbucket Pipeline,
//! Bitquery, Blackboard, BlockCypher, BlueJeans, Bluesky, and BlueSnap detectors against
//! zero-width spaces, soft hyphens, combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. BIGCOMMERCE STORE API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv14_bigcommerce_store_normal_must_fire() {
    assert_detector_fires(
        "bigcommerce-store-api-credentials",
        "bigcommerce_store_hash = \"abcde123\"",
        "abcde123",
    );
}

#[test]
fn adv14_bigcommerce_store_wrong_prefix_must_silent() {
    assert_detector_silent(
        "bigcommerce-store-api-credentials",
        "smallcommerce_store_hash = \"abcde123\"",
    );
}

#[test]
fn adv14_bigcommerce_store_evade_zwsp_must_fire() {
    assert_detector_fires(
        "bigcommerce-store-api-credentials",
        "bigcommerce\u{200B}_store_hash = \"abcde123\"",
        "abcde123",
    );
}

#[test]
fn adv14_bigcommerce_store_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "bigcommerce-store-api-credentials",
        "bigcommerce_store_hash = \"abcde\u{00AD}123\"",
        "abcde123",
    );
}

#[test]
fn adv14_bigcommerce_store_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "bigcommerce-store-api-credentials",
        "b\u{0457}gcommerce_store_hash = \"abcde123\"",
        "abcde123",
    );
}

// =========================================================================
// 2. BING MAPS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv14_bing_normal_must_fire() {
    assert_detector_fires(
        "bing-maps-api-key",
        "BING_MAPS_KEY = \"abcde1234567890abcde123456789012abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv14_bing_wrong_prefix_must_silent() {
    assert_detector_silent(
        "bing-maps-api-key",
        "RING_MAPS_KEY = \"abcde1234567890abcde123456789012abcde1234567890abcde123456789012\"",
    );
}

#[test]
fn adv14_bing_evade_zwsp_must_fire() {
    assert_detector_fires("bing-maps-api-key", "BING\u{200B}_MAPS_KEY = \"abcde1234567890abcde123456789012abcde1234567890abcde123456789012\"", "abcde1234567890abcde123456789012abcde1234567890abcde123456789012");
}

#[test]
fn adv14_bing_evade_soft_hyphen_must_fire() {
    assert_detector_fires("bing-maps-api-key", "BING_MAPS_KEY = \"abcde1234567890abcde1\u{00AD}23456789012abcde1234567890abcde123456789012\"", "abcde1234567890abcde123456789012abcde1234567890abcde123456789012");
}

#[test]
fn adv14_bing_evade_homoglyph_must_fire() {
    assert_detector_fires("bing-maps-api-key", "b\u{0457}ng_maps_key = \"abcde1234567890abcde123456789012abcde1234567890abcde123456789012\"", "abcde1234567890abcde123456789012abcde1234567890abcde123456789012");
}

// =========================================================================
// 3. BITBUCKET APP PASSWORD ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv14_bitbucket_password_normal_must_fire() {
    assert_detector_fires(
        "bitbucket-app-password",
        "bitbucket_app_password = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv14_bitbucket_password_wrong_prefix_must_silent() {
    assert_detector_silent(
        "bitbucket-app-password",
        "fitbucket_app_password = \"abcde1234567890abcde123456789012\"",
    );
}

#[test]
fn adv14_bitbucket_password_evade_zwsp_must_fire() {
    assert_detector_fires(
        "bitbucket-app-password",
        "bitbucket\u{200B}_app_password = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv14_bitbucket_password_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "bitbucket-app-password",
        "bitbucket_app_password = \"abcde1234567890abcde1\u{00AD}23456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv14_bitbucket_password_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "bitbucket-app-password",
        "b\u{0457}tbucket_app_password = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

// =========================================================================
// 4. BITBUCKET PIPELINE VARIABLE ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv14_bitbucket_pipeline_normal_must_fire() {
    assert_detector_fires(
        "bitbucket-pipeline-variable",
        "BITBUCKET_PASSWORD = \"abcde1234567890a\"",
        "abcde1234567890a",
    );
}

#[test]
fn adv14_bitbucket_pipeline_wrong_prefix_must_silent() {
    assert_detector_silent(
        "bitbucket-pipeline-variable",
        "MITBUCKET_PASSWORD = \"abcde1234567890a\"",
    );
}

#[test]
fn adv14_bitbucket_pipeline_evade_zwsp_must_fire() {
    assert_detector_fires(
        "bitbucket-pipeline-variable",
        "BITBUCKET\u{200B}_PASSWORD = \"abcde1234567890a\"",
        "abcde1234567890a",
    );
}

#[test]
fn adv14_bitbucket_pipeline_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "bitbucket-pipeline-variable",
        "BITBUCKET_PASSWORD = \"abcde12345\u{00AD}67890a\"",
        "abcde1234567890a",
    );
}

#[test]
fn adv14_bitbucket_pipeline_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "bitbucket-pipeline-variable",
        "b\u{0457}tbucket_pipeline = \"abcde1234567890a\"",
        "abcde1234567890a",
    );
}

// =========================================================================
// 5. BITQUERY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv14_bitquery_normal_must_fire() {
    assert_detector_fires(
        "bitquery-api-key",
        "bitquery_api_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv14_bitquery_wrong_prefix_must_silent() {
    assert_detector_silent(
        "bitquery-api-key",
        "gitquery_api_key = \"abcde1234567890abcde123456789012\"",
    );
}

#[test]
fn adv14_bitquery_evade_zwsp_must_fire() {
    assert_detector_fires(
        "bitquery-api-key",
        "bitquery\u{200B}_api_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv14_bitquery_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "bitquery-api-key",
        "bitquery_api_key = \"abcde1234567890abcde1\u{00AD}23456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv14_bitquery_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "bitquery-api-key",
        "b\u{0457}tquery_api_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

// =========================================================================
// 6. BLACKBOARD API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv14_blackboard_normal_must_fire() {
    assert_detector_fires(
        "blackboard-api-credentials",
        "blackboard_client_id = \"12345678-abcd-1234-abcd-1234567890ab\"",
        "12345678-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv14_blackboard_wrong_prefix_must_silent() {
    assert_detector_silent(
        "blackboard-api-credentials",
        "whiteboard_client_id = \"12345678-abcd-1234-abcd-1234567890ab\"",
    );
}

#[test]
fn adv14_blackboard_evade_zwsp_must_fire() {
    assert_detector_fires(
        "blackboard-api-credentials",
        "blackboard\u{200B}_client_id = \"12345678-abcd-1234-abcd-1234567890ab\"",
        "12345678-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv14_blackboard_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "blackboard-api-credentials",
        "blackboard_client_id = \"12345678-abcd-1234-abcd-12345678\u{00AD}90ab\"",
        "12345678-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv14_blackboard_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "blackboard-api-credentials",
        "blackb\u{043E}ard_client_id = \"12345678-abcd-1234-abcd-1234567890ab\"",
        "12345678-abcd-1234-abcd-1234567890ab",
    );
}

// =========================================================================
// 7. BLOCKCYPHER API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv14_blockcypher_normal_must_fire() {
    assert_detector_fires(
        "blockcypher-api-token",
        "blockcypher_token = \"abcde1234567890abcde1234\"",
        "abcde1234567890abcde1234",
    );
}

#[test]
fn adv14_blockcypher_wrong_prefix_must_silent() {
    assert_detector_silent(
        "blockcypher-api-token",
        "blockcipher_token = \"abcde1234567890abcde1234\"",
    );
}

#[test]
fn adv14_blockcypher_evade_zwsp_must_fire() {
    assert_detector_fires(
        "blockcypher-api-token",
        "blockcypher\u{200B}_token = \"abcde1234567890abcde1234\"",
        "abcde1234567890abcde1234",
    );
}

#[test]
fn adv14_blockcypher_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "blockcypher-api-token",
        "blockcypher_token = \"abcde12345\u{00AD}67890abcde1234\"",
        "abcde1234567890abcde1234",
    );
}

#[test]
fn adv14_blockcypher_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "blockcypher-api-token",
        "blockc\u{0443}pher_token = \"abcde1234567890abcde1234\"",
        "abcde1234567890abcde1234",
    );
}

// =========================================================================
// 8. BLUEJEANS API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv14_bluejeans_normal_must_fire() {
    assert_detector_fires(
        "bluejeans-api",
        "bluejeans_api_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv14_bluejeans_wrong_prefix_must_silent() {
    assert_detector_silent(
        "bluejeans-api",
        "greenjeans_api_key = \"abcde1234567890abcde123456789012\"",
    );
}

#[test]
fn adv14_bluejeans_evade_zwsp_must_fire() {
    assert_detector_fires(
        "bluejeans-api",
        "bluejeans\u{200B}_api_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv14_bluejeans_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "bluejeans-api",
        "bluejeans_api_key = \"abcde1234567890abcde1\u{00AD}23456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv14_bluejeans_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "bluejeans-api",
        "bluej\u{0435}ans_api_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

// =========================================================================
// 9. BLUESKY APP PASSWORD ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv14_bluesky_normal_must_fire() {
    assert_detector_fires(
        "bluesky-app-password",
        "bsky_app_password = \"abcd-efgh-ijkl-mnop\"",
        "abcd-efgh-ijkl-mnop",
    );
}

#[test]
fn adv14_bluesky_wrong_prefix_must_silent() {
    assert_detector_silent(
        "bluesky-app-password",
        "gsky_app_passwurd = \"abcd-efgh-ijkl-mnop\"",
    );
}

#[test]
fn adv14_bluesky_evade_zwsp_must_fire() {
    assert_detector_fires(
        "bluesky-app-password",
        "bsky\u{200B}_app_password = \"abcd-efgh-ijkl-mnop\"",
        "abcd-efgh-ijkl-mnop",
    );
}

#[test]
fn adv14_bluesky_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "bluesky-app-password",
        "bsky_app_password = \"abcd-efgh-ij\u{00AD}kl-mnop\"",
        "abcd-efgh-ijkl-mnop",
    );
}

#[test]
fn adv14_bluesky_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "bluesky-app-password",
        "bsk\u{0443}_app_password = \"abcd-efgh-ijkl-mnop\"",
        "abcd-efgh-ijkl-mnop",
    );
}

// =========================================================================
// 10. BLUESNAP API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv14_bluesnap_normal_must_fire() {
    assert_detector_fires(
        "bluesnap-api-credentials",
        "bluesnap_api_user = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv14_bluesnap_wrong_prefix_must_silent() {
    assert_detector_silent(
        "bluesnap-api-credentials",
        "redsnap_api_user = \"abcde1234567890abcde\"",
    );
}

#[test]
fn adv14_bluesnap_evade_zwsp_must_fire() {
    assert_detector_fires(
        "bluesnap-api-credentials",
        "bluesnap\u{200B}_api_user = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv14_bluesnap_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "bluesnap-api-credentials",
        "bluesnap_api_user = \"abcde12345\u{00AD}67890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv14_bluesnap_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "bluesnap-api-credentials",
        "bluesn\u{0430}p_api_user = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}
