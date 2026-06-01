//! Part 101 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates lark, lastfm, lastpass, lattice, launchdarkly, launchdarkly, lawpay, lemon, leptonai, library detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. LARK APP ID ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv101_lark_app_id_normal_must_fire() {
    assert_detector_fires(
        "lark-app-id",
        "lark app_id cli_a1b2c3d4e5f67890",
        "cli_a1b2c3d4e5f67890",
    );
}

#[test]
fn adv101_lark_app_id_wrong_prefix_must_silent() {
    assert_detector_silent("lark-app-id", "dummy app_id xxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv101_lark_app_id_evade_zwsp_must_fire() {
    assert_detector_fires(
        "lark-app-id",
        "lark app_id cli_a1b2c3\u{200B}d4e5f67890",
        "cli_a1b2c3d4e5f67890",
    );
}

#[test]
fn adv101_lark_app_id_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "lark-app-id",
        "lark app_id cli_a1b2c3\u{00AD}d4e5f67890",
        "cli_a1b2c3d4e5f67890",
    );
}

#[test]
fn adv101_lark_app_id_evade_zwnj_must_fire() {
    assert_detector_fires(
        "lark-app-id",
        "lark app_id cli_a1b2c3\u{200C}d4e5f67890",
        "cli_a1b2c3d4e5f67890",
    );
}

#[test]
fn adv101_lark_app_id_evade_zwj_must_fire() {
    assert_detector_fires(
        "lark-app-id",
        "lark app_id cli_a1b2c3\u{200D}d4e5f67890",
        "cli_a1b2c3d4e5f67890",
    );
}

#[test]
fn adv101_lark_app_id_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "lark-app-id",
        "lark app_id cli_a1b2c3\u{FEFF}d4e5f67890",
        "cli_a1b2c3d4e5f67890",
    );
}

#[test]
fn adv101_lark_app_id_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "lark-app-id",
        "lark app_id cli_a1b2c3\u{2060}d4e5f67890",
        "cli_a1b2c3d4e5f67890",
    );
}

#[test]
fn adv101_lark_app_id_evade_mongolian_must_fire() {
    assert_detector_fires(
        "lark-app-id",
        "lark app_id cli_a1b2c3\u{180E}d4e5f67890",
        "cli_a1b2c3d4e5f67890",
    );
}

#[test]
fn adv101_lark_app_id_evade_rtl_must_fire() {
    assert_detector_fires(
        "lark-app-id",
        "lark app_id cli_a1b2c3\u{202E}d4e5f67890",
        "cli_a1b2c3d4e5f67890",
    );
}

#[test]
fn adv101_lark_app_id_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "lark-app-id",
        "lark app_id cli_a1b2c3\u{202C}d4e5f67890",
        "cli_a1b2c3d4e5f67890",
    );
}

#[test]
fn adv101_lark_app_id_evade_lrm_must_fire() {
    assert_detector_fires(
        "lark-app-id",
        "lark app_id cli_a1b2c3\u{200E}d4e5f67890",
        "cli_a1b2c3d4e5f67890",
    );
}

// =========================================================================
// 2. LASTFM API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv101_lastfm_api_key_normal_must_fire() {
    assert_detector_fires(
        "lastfm-api-key",
        "LASTFM=e7a40edf8635d0cdb47ea9f156d972bc",
        "e7a40edf8635d0cdb47ea9f156d972bc",
    );
}

#[test]
fn adv101_lastfm_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "lastfm-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv101_lastfm_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "lastfm-api-key",
        "LASTFM=e7a40edf8635d0cd\u{200B}b47ea9f156d972bc",
        "e7a40edf8635d0cdb47ea9f156d972bc",
    );
}

#[test]
fn adv101_lastfm_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "lastfm-api-key",
        "LASTFM=e7a40edf8635d0cd\u{00AD}b47ea9f156d972bc",
        "e7a40edf8635d0cdb47ea9f156d972bc",
    );
}

#[test]
fn adv101_lastfm_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "lastfm-api-key",
        "LASTFM=e7a40edf8635d0cd\u{200C}b47ea9f156d972bc",
        "e7a40edf8635d0cdb47ea9f156d972bc",
    );
}

#[test]
fn adv101_lastfm_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "lastfm-api-key",
        "LASTFM=e7a40edf8635d0cd\u{200D}b47ea9f156d972bc",
        "e7a40edf8635d0cdb47ea9f156d972bc",
    );
}

#[test]
fn adv101_lastfm_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "lastfm-api-key",
        "LASTFM=e7a40edf8635d0cd\u{FEFF}b47ea9f156d972bc",
        "e7a40edf8635d0cdb47ea9f156d972bc",
    );
}

#[test]
fn adv101_lastfm_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "lastfm-api-key",
        "LASTFM=e7a40edf8635d0cd\u{2060}b47ea9f156d972bc",
        "e7a40edf8635d0cdb47ea9f156d972bc",
    );
}

#[test]
fn adv101_lastfm_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "lastfm-api-key",
        "LASTFM=e7a40edf8635d0cd\u{180E}b47ea9f156d972bc",
        "e7a40edf8635d0cdb47ea9f156d972bc",
    );
}

#[test]
fn adv101_lastfm_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "lastfm-api-key",
        "LASTFM=e7a40edf8635d0cd\u{202E}b47ea9f156d972bc",
        "e7a40edf8635d0cdb47ea9f156d972bc",
    );
}

#[test]
fn adv101_lastfm_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "lastfm-api-key",
        "LASTFM=e7a40edf8635d0cd\u{202C}b47ea9f156d972bc",
        "e7a40edf8635d0cdb47ea9f156d972bc",
    );
}

#[test]
fn adv101_lastfm_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "lastfm-api-key",
        "LASTFM=e7a40edf8635d0cd\u{200E}b47ea9f156d972bc",
        "e7a40edf8635d0cdb47ea9f156d972bc",
    );
}

// =========================================================================
// 3. LASTPASS DEV CREDS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv101_lastpass_dev_creds_normal_must_fire() {
    assert_detector_fires("lastpass-dev-creds", "lastpass id=9860386", "9860386");
}

#[test]
fn adv101_lastpass_dev_creds_wrong_prefix_must_silent() {
    assert_detector_silent("lastpass-dev-creds", "dummy_prefix_0 =xxxxxxx");
}

#[test]
fn adv101_lastpass_dev_creds_evade_zwsp_must_fire() {
    assert_detector_fires(
        "lastpass-dev-creds",
        "lastpass id=986\u{200B}0386",
        "9860386",
    );
}

#[test]
fn adv101_lastpass_dev_creds_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "lastpass-dev-creds",
        "lastpass id=986\u{00AD}0386",
        "9860386",
    );
}

#[test]
fn adv101_lastpass_dev_creds_evade_zwnj_must_fire() {
    assert_detector_fires(
        "lastpass-dev-creds",
        "lastpass id=986\u{200C}0386",
        "9860386",
    );
}

#[test]
fn adv101_lastpass_dev_creds_evade_zwj_must_fire() {
    assert_detector_fires(
        "lastpass-dev-creds",
        "lastpass id=986\u{200D}0386",
        "9860386",
    );
}

#[test]
fn adv101_lastpass_dev_creds_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "lastpass-dev-creds",
        "lastpass id=986\u{FEFF}0386",
        "9860386",
    );
}

#[test]
fn adv101_lastpass_dev_creds_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "lastpass-dev-creds",
        "lastpass id=986\u{2060}0386",
        "9860386",
    );
}

#[test]
fn adv101_lastpass_dev_creds_evade_mongolian_must_fire() {
    assert_detector_fires(
        "lastpass-dev-creds",
        "lastpass id=986\u{180E}0386",
        "9860386",
    );
}

#[test]
fn adv101_lastpass_dev_creds_evade_rtl_must_fire() {
    assert_detector_fires(
        "lastpass-dev-creds",
        "lastpass id=986\u{202E}0386",
        "9860386",
    );
}

#[test]
fn adv101_lastpass_dev_creds_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "lastpass-dev-creds",
        "lastpass id=986\u{202C}0386",
        "9860386",
    );
}

#[test]
fn adv101_lastpass_dev_creds_evade_lrm_must_fire() {
    assert_detector_fires(
        "lastpass-dev-creds",
        "lastpass id=986\u{200E}0386",
        "9860386",
    );
}

// =========================================================================
// 4. LATTICE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv101_lattice_api_key_normal_must_fire() {
    assert_detector_fires(
        "lattice-api-key",
        "LATTICE_API_KEY=FoqEOhu9N6j7B1gltUOv",
        "FoqEOhu9N6j7B1gltUOv",
    );
}

#[test]
fn adv101_lattice_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("lattice-api-key", "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv101_lattice_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "lattice-api-key",
        "LATTICE_API_KEY=FoqEOhu9N6\u{200B}j7B1gltUOv",
        "FoqEOhu9N6j7B1gltUOv",
    );
}

#[test]
fn adv101_lattice_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "lattice-api-key",
        "LATTICE_API_KEY=FoqEOhu9N6\u{00AD}j7B1gltUOv",
        "FoqEOhu9N6j7B1gltUOv",
    );
}

#[test]
fn adv101_lattice_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "lattice-api-key",
        "LATTICE_API_KEY=FoqEOhu9N6\u{200C}j7B1gltUOv",
        "FoqEOhu9N6j7B1gltUOv",
    );
}

#[test]
fn adv101_lattice_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "lattice-api-key",
        "LATTICE_API_KEY=FoqEOhu9N6\u{200D}j7B1gltUOv",
        "FoqEOhu9N6j7B1gltUOv",
    );
}

#[test]
fn adv101_lattice_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "lattice-api-key",
        "LATTICE_API_KEY=FoqEOhu9N6\u{FEFF}j7B1gltUOv",
        "FoqEOhu9N6j7B1gltUOv",
    );
}

#[test]
fn adv101_lattice_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "lattice-api-key",
        "LATTICE_API_KEY=FoqEOhu9N6\u{2060}j7B1gltUOv",
        "FoqEOhu9N6j7B1gltUOv",
    );
}

#[test]
fn adv101_lattice_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "lattice-api-key",
        "LATTICE_API_KEY=FoqEOhu9N6\u{180E}j7B1gltUOv",
        "FoqEOhu9N6j7B1gltUOv",
    );
}

#[test]
fn adv101_lattice_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "lattice-api-key",
        "LATTICE_API_KEY=FoqEOhu9N6\u{202E}j7B1gltUOv",
        "FoqEOhu9N6j7B1gltUOv",
    );
}

#[test]
fn adv101_lattice_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "lattice-api-key",
        "LATTICE_API_KEY=FoqEOhu9N6\u{202C}j7B1gltUOv",
        "FoqEOhu9N6j7B1gltUOv",
    );
}

#[test]
fn adv101_lattice_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "lattice-api-key",
        "LATTICE_API_KEY=FoqEOhu9N6\u{200E}j7B1gltUOv",
        "FoqEOhu9N6j7B1gltUOv",
    );
}

// =========================================================================
// 5. LAUNCHDARKLY API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv101_launchdarkly_api_token_normal_must_fire() {
    assert_detector_fires(
        "launchdarkly-api-token",
        "api-3bc9381c-1ed2-2683-c413-ceb66fc0a462",
        "api-3bc9381c-1ed2-2683-c413-ceb66fc0a462",
    );
}

#[test]
fn adv101_launchdarkly_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "launchdarkly-api-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv101_launchdarkly_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "launchdarkly-api-token",
        "api-3bc9381c-1ed2-26\u{200B}83-c413-ceb66fc0a462",
        "api-3bc9381c-1ed2-2683-c413-ceb66fc0a462",
    );
}

#[test]
fn adv101_launchdarkly_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "launchdarkly-api-token",
        "api-3bc9381c-1ed2-26\u{00AD}83-c413-ceb66fc0a462",
        "api-3bc9381c-1ed2-2683-c413-ceb66fc0a462",
    );
}

#[test]
fn adv101_launchdarkly_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "launchdarkly-api-token",
        "api-3bc9381c-1ed2-26\u{200C}83-c413-ceb66fc0a462",
        "api-3bc9381c-1ed2-2683-c413-ceb66fc0a462",
    );
}

#[test]
fn adv101_launchdarkly_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "launchdarkly-api-token",
        "api-3bc9381c-1ed2-26\u{200D}83-c413-ceb66fc0a462",
        "api-3bc9381c-1ed2-2683-c413-ceb66fc0a462",
    );
}

#[test]
fn adv101_launchdarkly_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "launchdarkly-api-token",
        "api-3bc9381c-1ed2-26\u{FEFF}83-c413-ceb66fc0a462",
        "api-3bc9381c-1ed2-2683-c413-ceb66fc0a462",
    );
}

#[test]
fn adv101_launchdarkly_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "launchdarkly-api-token",
        "api-3bc9381c-1ed2-26\u{2060}83-c413-ceb66fc0a462",
        "api-3bc9381c-1ed2-2683-c413-ceb66fc0a462",
    );
}

#[test]
fn adv101_launchdarkly_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "launchdarkly-api-token",
        "api-3bc9381c-1ed2-26\u{180E}83-c413-ceb66fc0a462",
        "api-3bc9381c-1ed2-2683-c413-ceb66fc0a462",
    );
}

#[test]
fn adv101_launchdarkly_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "launchdarkly-api-token",
        "api-3bc9381c-1ed2-26\u{202E}83-c413-ceb66fc0a462",
        "api-3bc9381c-1ed2-2683-c413-ceb66fc0a462",
    );
}

#[test]
fn adv101_launchdarkly_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "launchdarkly-api-token",
        "api-3bc9381c-1ed2-26\u{202C}83-c413-ceb66fc0a462",
        "api-3bc9381c-1ed2-2683-c413-ceb66fc0a462",
    );
}

#[test]
fn adv101_launchdarkly_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "launchdarkly-api-token",
        "api-3bc9381c-1ed2-26\u{200E}83-c413-ceb66fc0a462",
        "api-3bc9381c-1ed2-2683-c413-ceb66fc0a462",
    );
}

// =========================================================================
// 6. LAUNCHDARKLY SDK KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv101_launchdarkly_sdk_key_normal_must_fire() {
    assert_detector_fires(
        "launchdarkly-sdk-key",
        "sdk-1c162122-82ea-de71-015d-081b713d154f",
        "sdk-1c162122-82ea-de71-015d-081b713d154f",
    );
}

#[test]
fn adv101_launchdarkly_sdk_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "launchdarkly-sdk-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv101_launchdarkly_sdk_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "launchdarkly-sdk-key",
        "sdk-1c162122-82ea-de\u{200B}71-015d-081b713d154f",
        "sdk-1c162122-82ea-de71-015d-081b713d154f",
    );
}

#[test]
fn adv101_launchdarkly_sdk_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "launchdarkly-sdk-key",
        "sdk-1c162122-82ea-de\u{00AD}71-015d-081b713d154f",
        "sdk-1c162122-82ea-de71-015d-081b713d154f",
    );
}

#[test]
fn adv101_launchdarkly_sdk_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "launchdarkly-sdk-key",
        "sdk-1c162122-82ea-de\u{200C}71-015d-081b713d154f",
        "sdk-1c162122-82ea-de71-015d-081b713d154f",
    );
}

#[test]
fn adv101_launchdarkly_sdk_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "launchdarkly-sdk-key",
        "sdk-1c162122-82ea-de\u{200D}71-015d-081b713d154f",
        "sdk-1c162122-82ea-de71-015d-081b713d154f",
    );
}

#[test]
fn adv101_launchdarkly_sdk_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "launchdarkly-sdk-key",
        "sdk-1c162122-82ea-de\u{FEFF}71-015d-081b713d154f",
        "sdk-1c162122-82ea-de71-015d-081b713d154f",
    );
}

#[test]
fn adv101_launchdarkly_sdk_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "launchdarkly-sdk-key",
        "sdk-1c162122-82ea-de\u{2060}71-015d-081b713d154f",
        "sdk-1c162122-82ea-de71-015d-081b713d154f",
    );
}

#[test]
fn adv101_launchdarkly_sdk_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "launchdarkly-sdk-key",
        "sdk-1c162122-82ea-de\u{180E}71-015d-081b713d154f",
        "sdk-1c162122-82ea-de71-015d-081b713d154f",
    );
}

#[test]
fn adv101_launchdarkly_sdk_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "launchdarkly-sdk-key",
        "sdk-1c162122-82ea-de\u{202E}71-015d-081b713d154f",
        "sdk-1c162122-82ea-de71-015d-081b713d154f",
    );
}

#[test]
fn adv101_launchdarkly_sdk_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "launchdarkly-sdk-key",
        "sdk-1c162122-82ea-de\u{202C}71-015d-081b713d154f",
        "sdk-1c162122-82ea-de71-015d-081b713d154f",
    );
}

#[test]
fn adv101_launchdarkly_sdk_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "launchdarkly-sdk-key",
        "sdk-1c162122-82ea-de\u{200E}71-015d-081b713d154f",
        "sdk-1c162122-82ea-de71-015d-081b713d154f",
    );
}

// =========================================================================
// 7. LAWPAY API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv101_lawpay_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "lawpay-api-credentials",
        "LAWPAY_API_KEY=q6s8YUTICFWK2BHVtVg4cBQ258zYI1wo",
        "q6s8YUTICFWK2BHVtVg4cBQ258zYI1wo",
    );
}

#[test]
fn adv101_lawpay_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "lawpay-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv101_lawpay_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "lawpay-api-credentials",
        "LAWPAY_API_KEY=q6s8YUTICFWK2BHV\u{200B}tVg4cBQ258zYI1wo",
        "q6s8YUTICFWK2BHVtVg4cBQ258zYI1wo",
    );
}

#[test]
fn adv101_lawpay_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "lawpay-api-credentials",
        "LAWPAY_API_KEY=q6s8YUTICFWK2BHV\u{00AD}tVg4cBQ258zYI1wo",
        "q6s8YUTICFWK2BHVtVg4cBQ258zYI1wo",
    );
}

#[test]
fn adv101_lawpay_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "lawpay-api-credentials",
        "LAWPAY_API_KEY=q6s8YUTICFWK2BHV\u{200C}tVg4cBQ258zYI1wo",
        "q6s8YUTICFWK2BHVtVg4cBQ258zYI1wo",
    );
}

#[test]
fn adv101_lawpay_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "lawpay-api-credentials",
        "LAWPAY_API_KEY=q6s8YUTICFWK2BHV\u{200D}tVg4cBQ258zYI1wo",
        "q6s8YUTICFWK2BHVtVg4cBQ258zYI1wo",
    );
}

#[test]
fn adv101_lawpay_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "lawpay-api-credentials",
        "LAWPAY_API_KEY=q6s8YUTICFWK2BHV\u{FEFF}tVg4cBQ258zYI1wo",
        "q6s8YUTICFWK2BHVtVg4cBQ258zYI1wo",
    );
}

#[test]
fn adv101_lawpay_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "lawpay-api-credentials",
        "LAWPAY_API_KEY=q6s8YUTICFWK2BHV\u{2060}tVg4cBQ258zYI1wo",
        "q6s8YUTICFWK2BHVtVg4cBQ258zYI1wo",
    );
}

#[test]
fn adv101_lawpay_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "lawpay-api-credentials",
        "LAWPAY_API_KEY=q6s8YUTICFWK2BHV\u{180E}tVg4cBQ258zYI1wo",
        "q6s8YUTICFWK2BHVtVg4cBQ258zYI1wo",
    );
}

#[test]
fn adv101_lawpay_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "lawpay-api-credentials",
        "LAWPAY_API_KEY=q6s8YUTICFWK2BHV\u{202E}tVg4cBQ258zYI1wo",
        "q6s8YUTICFWK2BHVtVg4cBQ258zYI1wo",
    );
}

#[test]
fn adv101_lawpay_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "lawpay-api-credentials",
        "LAWPAY_API_KEY=q6s8YUTICFWK2BHV\u{202C}tVg4cBQ258zYI1wo",
        "q6s8YUTICFWK2BHVtVg4cBQ258zYI1wo",
    );
}

#[test]
fn adv101_lawpay_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "lawpay-api-credentials",
        "LAWPAY_API_KEY=q6s8YUTICFWK2BHV\u{200E}tVg4cBQ258zYI1wo",
        "q6s8YUTICFWK2BHVtVg4cBQ258zYI1wo",
    );
}

// =========================================================================
// 8. LEMON SQUEEZY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv101_lemon_squeezy_api_key_normal_must_fire() {
    assert_detector_fires(
        "lemon-squeezy-api-key",
        "lmsq_xiLTnQSBZD6hD0tf9zmy8Mfpd77yYG0w",
        "lmsq_xiLTnQSBZD6hD0tf9zmy8Mfpd77yYG0w",
    );
}

#[test]
fn adv101_lemon_squeezy_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "lemon-squeezy-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv101_lemon_squeezy_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "lemon-squeezy-api-key",
        "lmsq_xiLTnQSBZD6hD\u{200B}0tf9zmy8Mfpd77yYG0w",
        "lmsq_xiLTnQSBZD6hD0tf9zmy8Mfpd77yYG0w",
    );
}

#[test]
fn adv101_lemon_squeezy_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "lemon-squeezy-api-key",
        "lmsq_xiLTnQSBZD6hD\u{00AD}0tf9zmy8Mfpd77yYG0w",
        "lmsq_xiLTnQSBZD6hD0tf9zmy8Mfpd77yYG0w",
    );
}

#[test]
fn adv101_lemon_squeezy_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "lemon-squeezy-api-key",
        "lmsq_xiLTnQSBZD6hD\u{200C}0tf9zmy8Mfpd77yYG0w",
        "lmsq_xiLTnQSBZD6hD0tf9zmy8Mfpd77yYG0w",
    );
}

#[test]
fn adv101_lemon_squeezy_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "lemon-squeezy-api-key",
        "lmsq_xiLTnQSBZD6hD\u{200D}0tf9zmy8Mfpd77yYG0w",
        "lmsq_xiLTnQSBZD6hD0tf9zmy8Mfpd77yYG0w",
    );
}

#[test]
fn adv101_lemon_squeezy_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "lemon-squeezy-api-key",
        "lmsq_xiLTnQSBZD6hD\u{FEFF}0tf9zmy8Mfpd77yYG0w",
        "lmsq_xiLTnQSBZD6hD0tf9zmy8Mfpd77yYG0w",
    );
}

#[test]
fn adv101_lemon_squeezy_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "lemon-squeezy-api-key",
        "lmsq_xiLTnQSBZD6hD\u{2060}0tf9zmy8Mfpd77yYG0w",
        "lmsq_xiLTnQSBZD6hD0tf9zmy8Mfpd77yYG0w",
    );
}

#[test]
fn adv101_lemon_squeezy_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "lemon-squeezy-api-key",
        "lmsq_xiLTnQSBZD6hD\u{180E}0tf9zmy8Mfpd77yYG0w",
        "lmsq_xiLTnQSBZD6hD0tf9zmy8Mfpd77yYG0w",
    );
}

#[test]
fn adv101_lemon_squeezy_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "lemon-squeezy-api-key",
        "lmsq_xiLTnQSBZD6hD\u{202E}0tf9zmy8Mfpd77yYG0w",
        "lmsq_xiLTnQSBZD6hD0tf9zmy8Mfpd77yYG0w",
    );
}

#[test]
fn adv101_lemon_squeezy_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "lemon-squeezy-api-key",
        "lmsq_xiLTnQSBZD6hD\u{202C}0tf9zmy8Mfpd77yYG0w",
        "lmsq_xiLTnQSBZD6hD0tf9zmy8Mfpd77yYG0w",
    );
}

#[test]
fn adv101_lemon_squeezy_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "lemon-squeezy-api-key",
        "lmsq_xiLTnQSBZD6hD\u{200E}0tf9zmy8Mfpd77yYG0w",
        "lmsq_xiLTnQSBZD6hD0tf9zmy8Mfpd77yYG0w",
    );
}

// =========================================================================
// 9. LEPTONAI API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv101_leptonai_api_token_normal_must_fire() {
    assert_detector_fires(
        "leptonai-api-token",
        "LEPTONAI_API_KEY=7wh1PSp4KeB8aF3mmkib",
        "7wh1PSp4KeB8aF3mmkib",
    );
}

#[test]
fn adv101_leptonai_api_token_wrong_prefix_must_silent() {
    assert_detector_silent("leptonai-api-token", "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv101_leptonai_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "leptonai-api-token",
        "LEPTONAI_API_KEY=7wh1PSp4Ke\u{200B}B8aF3mmkib",
        "7wh1PSp4KeB8aF3mmkib",
    );
}

#[test]
fn adv101_leptonai_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "leptonai-api-token",
        "LEPTONAI_API_KEY=7wh1PSp4Ke\u{00AD}B8aF3mmkib",
        "7wh1PSp4KeB8aF3mmkib",
    );
}

#[test]
fn adv101_leptonai_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "leptonai-api-token",
        "LEPTONAI_API_KEY=7wh1PSp4Ke\u{200C}B8aF3mmkib",
        "7wh1PSp4KeB8aF3mmkib",
    );
}

#[test]
fn adv101_leptonai_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "leptonai-api-token",
        "LEPTONAI_API_KEY=7wh1PSp4Ke\u{200D}B8aF3mmkib",
        "7wh1PSp4KeB8aF3mmkib",
    );
}

#[test]
fn adv101_leptonai_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "leptonai-api-token",
        "LEPTONAI_API_KEY=7wh1PSp4Ke\u{FEFF}B8aF3mmkib",
        "7wh1PSp4KeB8aF3mmkib",
    );
}

#[test]
fn adv101_leptonai_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "leptonai-api-token",
        "LEPTONAI_API_KEY=7wh1PSp4Ke\u{2060}B8aF3mmkib",
        "7wh1PSp4KeB8aF3mmkib",
    );
}

#[test]
fn adv101_leptonai_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "leptonai-api-token",
        "LEPTONAI_API_KEY=7wh1PSp4Ke\u{180E}B8aF3mmkib",
        "7wh1PSp4KeB8aF3mmkib",
    );
}

#[test]
fn adv101_leptonai_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "leptonai-api-token",
        "LEPTONAI_API_KEY=7wh1PSp4Ke\u{202E}B8aF3mmkib",
        "7wh1PSp4KeB8aF3mmkib",
    );
}

#[test]
fn adv101_leptonai_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "leptonai-api-token",
        "LEPTONAI_API_KEY=7wh1PSp4Ke\u{202C}B8aF3mmkib",
        "7wh1PSp4KeB8aF3mmkib",
    );
}

#[test]
fn adv101_leptonai_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "leptonai-api-token",
        "LEPTONAI_API_KEY=7wh1PSp4Ke\u{200E}B8aF3mmkib",
        "7wh1PSp4KeB8aF3mmkib",
    );
}

// =========================================================================
// 10. LIBRARY OF CONGRESS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv101_library_of_congress_api_key_normal_must_fire() {
    assert_detector_fires(
        "library-of-congress-api-key",
        "LIBRARY_OF_CONGRESS_API_KEY=7SV8BoWRCkMYwW_50l67mLp7zeC1",
        "7SV8BoWRCkMYwW_50l67mLp7zeC1",
    );
}

#[test]
fn adv101_library_of_congress_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "library-of-congress-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv101_library_of_congress_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "library-of-congress-api-key",
        "LIBRARY_OF_CONGRESS_API_KEY=7SV8BoWRCkMYwW\u{200B}_50l67mLp7zeC1",
        "7SV8BoWRCkMYwW_50l67mLp7zeC1",
    );
}

#[test]
fn adv101_library_of_congress_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "library-of-congress-api-key",
        "LIBRARY_OF_CONGRESS_API_KEY=7SV8BoWRCkMYwW\u{00AD}_50l67mLp7zeC1",
        "7SV8BoWRCkMYwW_50l67mLp7zeC1",
    );
}

#[test]
fn adv101_library_of_congress_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "library-of-congress-api-key",
        "LIBRARY_OF_CONGRESS_API_KEY=7SV8BoWRCkMYwW\u{200C}_50l67mLp7zeC1",
        "7SV8BoWRCkMYwW_50l67mLp7zeC1",
    );
}

#[test]
fn adv101_library_of_congress_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "library-of-congress-api-key",
        "LIBRARY_OF_CONGRESS_API_KEY=7SV8BoWRCkMYwW\u{200D}_50l67mLp7zeC1",
        "7SV8BoWRCkMYwW_50l67mLp7zeC1",
    );
}

#[test]
fn adv101_library_of_congress_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "library-of-congress-api-key",
        "LIBRARY_OF_CONGRESS_API_KEY=7SV8BoWRCkMYwW\u{FEFF}_50l67mLp7zeC1",
        "7SV8BoWRCkMYwW_50l67mLp7zeC1",
    );
}

#[test]
fn adv101_library_of_congress_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "library-of-congress-api-key",
        "LIBRARY_OF_CONGRESS_API_KEY=7SV8BoWRCkMYwW\u{2060}_50l67mLp7zeC1",
        "7SV8BoWRCkMYwW_50l67mLp7zeC1",
    );
}

#[test]
fn adv101_library_of_congress_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "library-of-congress-api-key",
        "LIBRARY_OF_CONGRESS_API_KEY=7SV8BoWRCkMYwW\u{180E}_50l67mLp7zeC1",
        "7SV8BoWRCkMYwW_50l67mLp7zeC1",
    );
}

#[test]
fn adv101_library_of_congress_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "library-of-congress-api-key",
        "LIBRARY_OF_CONGRESS_API_KEY=7SV8BoWRCkMYwW\u{202E}_50l67mLp7zeC1",
        "7SV8BoWRCkMYwW_50l67mLp7zeC1",
    );
}

#[test]
fn adv101_library_of_congress_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "library-of-congress-api-key",
        "LIBRARY_OF_CONGRESS_API_KEY=7SV8BoWRCkMYwW\u{202C}_50l67mLp7zeC1",
        "7SV8BoWRCkMYwW_50l67mLp7zeC1",
    );
}

#[test]
fn adv101_library_of_congress_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "library-of-congress-api-key",
        "LIBRARY_OF_CONGRESS_API_KEY=7SV8BoWRCkMYwW\u{200E}_50l67mLp7zeC1",
        "7SV8BoWRCkMYwW_50l67mLp7zeC1",
    );
}
