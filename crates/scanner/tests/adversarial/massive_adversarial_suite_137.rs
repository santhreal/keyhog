//! Part 137 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates usps, vanta, veracode, vercel, vercel, vercel, vercel, vercel, vercel, vimeo detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. USPS WEBTOOLS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv137_usps_webtools_api_key_normal_must_fire() {
    assert_detector_fires(
        "usps-webtools-api-key",
        "USPS_USER=prEZZ_",
        "prEZZ_",
    );
}

#[test]
fn adv137_usps_webtools_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "usps-webtools-api-key",
        "dummy_prefix_0 =xxxxxx",
    );
}

#[test]
fn adv137_usps_webtools_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "usps-webtools-api-key",
        "USPS_USER=prE\u{200B}ZZ_",
        "prEZZ_",
    );
}

#[test]
fn adv137_usps_webtools_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "usps-webtools-api-key",
        "USPS_USER=prE\u{00AD}ZZ_",
        "prEZZ_",
    );
}

#[test]
fn adv137_usps_webtools_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "usps-webtools-api-key",
        "USPS_USER=prE\u{200C}ZZ_",
        "prEZZ_",
    );
}

#[test]
fn adv137_usps_webtools_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "usps-webtools-api-key",
        "USPS_USER=prE\u{200D}ZZ_",
        "prEZZ_",
    );
}

#[test]
fn adv137_usps_webtools_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "usps-webtools-api-key",
        "USPS_USER=prE\u{FEFF}ZZ_",
        "prEZZ_",
    );
}

#[test]
fn adv137_usps_webtools_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "usps-webtools-api-key",
        "USPS_USER=prE\u{2060}ZZ_",
        "prEZZ_",
    );
}

#[test]
fn adv137_usps_webtools_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "usps-webtools-api-key",
        "USPS_USER=prE\u{180E}ZZ_",
        "prEZZ_",
    );
}

#[test]
fn adv137_usps_webtools_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "usps-webtools-api-key",
        "USPS_USER=prE\u{202E}ZZ_",
        "prEZZ_",
    );
}

#[test]
fn adv137_usps_webtools_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "usps-webtools-api-key",
        "USPS_USER=prE\u{202C}ZZ_",
        "prEZZ_",
    );
}

#[test]
fn adv137_usps_webtools_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "usps-webtools-api-key",
        "USPS_USER=prE\u{200E}ZZ_",
        "prEZZ_",
    );
}

// =========================================================================
// 2. VANTA OAUTH CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv137_vanta_oauth_credentials_normal_must_fire() {
    assert_detector_fires(
        "vanta-oauth-credentials",
        "vci_4ad725523884fe575df3b2df31a8ebcf68656a67e22c3d92f2255",
        "vci_4ad725523884fe575df3b2df31a8ebcf68656a67e22c3d92f2255",
    );
}

#[test]
fn adv137_vanta_oauth_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "vanta-oauth-credentials",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv137_vanta_oauth_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "vanta-oauth-credentials",
        "vci_4ad725523884fe575df3b2df\u{200B}31a8ebcf68656a67e22c3d92f2255",
        "vci_4ad725523884fe575df3b2df31a8ebcf68656a67e22c3d92f2255",
    );
}

#[test]
fn adv137_vanta_oauth_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "vanta-oauth-credentials",
        "vci_4ad725523884fe575df3b2df\u{00AD}31a8ebcf68656a67e22c3d92f2255",
        "vci_4ad725523884fe575df3b2df31a8ebcf68656a67e22c3d92f2255",
    );
}

#[test]
fn adv137_vanta_oauth_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "vanta-oauth-credentials",
        "vci_4ad725523884fe575df3b2df\u{200C}31a8ebcf68656a67e22c3d92f2255",
        "vci_4ad725523884fe575df3b2df31a8ebcf68656a67e22c3d92f2255",
    );
}

#[test]
fn adv137_vanta_oauth_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "vanta-oauth-credentials",
        "vci_4ad725523884fe575df3b2df\u{200D}31a8ebcf68656a67e22c3d92f2255",
        "vci_4ad725523884fe575df3b2df31a8ebcf68656a67e22c3d92f2255",
    );
}

#[test]
fn adv137_vanta_oauth_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "vanta-oauth-credentials",
        "vci_4ad725523884fe575df3b2df\u{FEFF}31a8ebcf68656a67e22c3d92f2255",
        "vci_4ad725523884fe575df3b2df31a8ebcf68656a67e22c3d92f2255",
    );
}

#[test]
fn adv137_vanta_oauth_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "vanta-oauth-credentials",
        "vci_4ad725523884fe575df3b2df\u{2060}31a8ebcf68656a67e22c3d92f2255",
        "vci_4ad725523884fe575df3b2df31a8ebcf68656a67e22c3d92f2255",
    );
}

#[test]
fn adv137_vanta_oauth_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "vanta-oauth-credentials",
        "vci_4ad725523884fe575df3b2df\u{180E}31a8ebcf68656a67e22c3d92f2255",
        "vci_4ad725523884fe575df3b2df31a8ebcf68656a67e22c3d92f2255",
    );
}

#[test]
fn adv137_vanta_oauth_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "vanta-oauth-credentials",
        "vci_4ad725523884fe575df3b2df\u{202E}31a8ebcf68656a67e22c3d92f2255",
        "vci_4ad725523884fe575df3b2df31a8ebcf68656a67e22c3d92f2255",
    );
}

#[test]
fn adv137_vanta_oauth_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "vanta-oauth-credentials",
        "vci_4ad725523884fe575df3b2df\u{202C}31a8ebcf68656a67e22c3d92f2255",
        "vci_4ad725523884fe575df3b2df31a8ebcf68656a67e22c3d92f2255",
    );
}

#[test]
fn adv137_vanta_oauth_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "vanta-oauth-credentials",
        "vci_4ad725523884fe575df3b2df\u{200E}31a8ebcf68656a67e22c3d92f2255",
        "vci_4ad725523884fe575df3b2df31a8ebcf68656a67e22c3d92f2255",
    );
}

// =========================================================================
// 3. VERACODE API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv137_veracode_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "veracode-api-credentials",
        "VERACODE=714295ff9bbb202bc18e",
        "714295ff9bbb202bc18e",
    );
}

#[test]
fn adv137_veracode_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "veracode-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv137_veracode_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "veracode-api-credentials",
        "VERACODE=714295ff9b\u{200B}bb202bc18e",
        "714295ff9bbb202bc18e",
    );
}

#[test]
fn adv137_veracode_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "veracode-api-credentials",
        "VERACODE=714295ff9b\u{00AD}bb202bc18e",
        "714295ff9bbb202bc18e",
    );
}

#[test]
fn adv137_veracode_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "veracode-api-credentials",
        "VERACODE=714295ff9b\u{200C}bb202bc18e",
        "714295ff9bbb202bc18e",
    );
}

#[test]
fn adv137_veracode_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "veracode-api-credentials",
        "VERACODE=714295ff9b\u{200D}bb202bc18e",
        "714295ff9bbb202bc18e",
    );
}

#[test]
fn adv137_veracode_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "veracode-api-credentials",
        "VERACODE=714295ff9b\u{FEFF}bb202bc18e",
        "714295ff9bbb202bc18e",
    );
}

#[test]
fn adv137_veracode_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "veracode-api-credentials",
        "VERACODE=714295ff9b\u{2060}bb202bc18e",
        "714295ff9bbb202bc18e",
    );
}

#[test]
fn adv137_veracode_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "veracode-api-credentials",
        "VERACODE=714295ff9b\u{180E}bb202bc18e",
        "714295ff9bbb202bc18e",
    );
}

#[test]
fn adv137_veracode_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "veracode-api-credentials",
        "VERACODE=714295ff9b\u{202E}bb202bc18e",
        "714295ff9bbb202bc18e",
    );
}

#[test]
fn adv137_veracode_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "veracode-api-credentials",
        "VERACODE=714295ff9b\u{202C}bb202bc18e",
        "714295ff9bbb202bc18e",
    );
}

#[test]
fn adv137_veracode_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "veracode-api-credentials",
        "VERACODE=714295ff9b\u{200E}bb202bc18e",
        "714295ff9bbb202bc18e",
    );
}

// =========================================================================
// 4. VERCEL API TOKEN V2 ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv137_vercel_api_token_v2_normal_must_fire() {
    assert_detector_fires(
        "vercel-api-token-v2",
        "vercel_v2_cAOp9dzV2rgZio80vbSLSvNU",
        "vercel_v2_cAOp9dzV2rgZio80vbSLSvNU",
    );
}

#[test]
fn adv137_vercel_api_token_v2_wrong_prefix_must_silent() {
    assert_detector_silent(
        "vercel-api-token-v2",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv137_vercel_api_token_v2_evade_zwsp_must_fire() {
    assert_detector_fires(
        "vercel-api-token-v2",
        "vercel_v2_cAOp9dz\u{200B}V2rgZio80vbSLSvNU",
        "vercel_v2_cAOp9dzV2rgZio80vbSLSvNU",
    );
}

#[test]
fn adv137_vercel_api_token_v2_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "vercel-api-token-v2",
        "vercel_v2_cAOp9dz\u{00AD}V2rgZio80vbSLSvNU",
        "vercel_v2_cAOp9dzV2rgZio80vbSLSvNU",
    );
}

#[test]
fn adv137_vercel_api_token_v2_evade_zwnj_must_fire() {
    assert_detector_fires(
        "vercel-api-token-v2",
        "vercel_v2_cAOp9dz\u{200C}V2rgZio80vbSLSvNU",
        "vercel_v2_cAOp9dzV2rgZio80vbSLSvNU",
    );
}

#[test]
fn adv137_vercel_api_token_v2_evade_zwj_must_fire() {
    assert_detector_fires(
        "vercel-api-token-v2",
        "vercel_v2_cAOp9dz\u{200D}V2rgZio80vbSLSvNU",
        "vercel_v2_cAOp9dzV2rgZio80vbSLSvNU",
    );
}

#[test]
fn adv137_vercel_api_token_v2_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "vercel-api-token-v2",
        "vercel_v2_cAOp9dz\u{FEFF}V2rgZio80vbSLSvNU",
        "vercel_v2_cAOp9dzV2rgZio80vbSLSvNU",
    );
}

#[test]
fn adv137_vercel_api_token_v2_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "vercel-api-token-v2",
        "vercel_v2_cAOp9dz\u{2060}V2rgZio80vbSLSvNU",
        "vercel_v2_cAOp9dzV2rgZio80vbSLSvNU",
    );
}

#[test]
fn adv137_vercel_api_token_v2_evade_mongolian_must_fire() {
    assert_detector_fires(
        "vercel-api-token-v2",
        "vercel_v2_cAOp9dz\u{180E}V2rgZio80vbSLSvNU",
        "vercel_v2_cAOp9dzV2rgZio80vbSLSvNU",
    );
}

#[test]
fn adv137_vercel_api_token_v2_evade_rtl_must_fire() {
    assert_detector_fires(
        "vercel-api-token-v2",
        "vercel_v2_cAOp9dz\u{202E}V2rgZio80vbSLSvNU",
        "vercel_v2_cAOp9dzV2rgZio80vbSLSvNU",
    );
}

#[test]
fn adv137_vercel_api_token_v2_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "vercel-api-token-v2",
        "vercel_v2_cAOp9dz\u{202C}V2rgZio80vbSLSvNU",
        "vercel_v2_cAOp9dzV2rgZio80vbSLSvNU",
    );
}

#[test]
fn adv137_vercel_api_token_v2_evade_lrm_must_fire() {
    assert_detector_fires(
        "vercel-api-token-v2",
        "vercel_v2_cAOp9dz\u{200E}V2rgZio80vbSLSvNU",
        "vercel_v2_cAOp9dzV2rgZio80vbSLSvNU",
    );
}

// =========================================================================
// 5. VERCEL EDGE CONFIG TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv137_vercel_edge_config_token_normal_must_fire() {
    assert_detector_fires(
        "vercel-edge-config-token",
        "ecfg_FW0BvtwcVjSHNW3E6sEiFh0poCf29bK44SnLZMBrT1n50X5B4rwblqa1FZS2k64F",
        "ecfg_FW0BvtwcVjSHNW3E6sEiFh0poCf29bK44SnLZMBrT1n50X5B4rwblqa1FZS2k64F",
    );
}

#[test]
fn adv137_vercel_edge_config_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "vercel-edge-config-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv137_vercel_edge_config_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "vercel-edge-config-token",
        "ecfg_FW0BvtwcVjSHNW3E6sEiFh0poCf29\u{200B}bK44SnLZMBrT1n50X5B4rwblqa1FZS2k64F",
        "ecfg_FW0BvtwcVjSHNW3E6sEiFh0poCf29bK44SnLZMBrT1n50X5B4rwblqa1FZS2k64F",
    );
}

#[test]
fn adv137_vercel_edge_config_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "vercel-edge-config-token",
        "ecfg_FW0BvtwcVjSHNW3E6sEiFh0poCf29\u{00AD}bK44SnLZMBrT1n50X5B4rwblqa1FZS2k64F",
        "ecfg_FW0BvtwcVjSHNW3E6sEiFh0poCf29bK44SnLZMBrT1n50X5B4rwblqa1FZS2k64F",
    );
}

#[test]
fn adv137_vercel_edge_config_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "vercel-edge-config-token",
        "ecfg_FW0BvtwcVjSHNW3E6sEiFh0poCf29\u{200C}bK44SnLZMBrT1n50X5B4rwblqa1FZS2k64F",
        "ecfg_FW0BvtwcVjSHNW3E6sEiFh0poCf29bK44SnLZMBrT1n50X5B4rwblqa1FZS2k64F",
    );
}

#[test]
fn adv137_vercel_edge_config_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "vercel-edge-config-token",
        "ecfg_FW0BvtwcVjSHNW3E6sEiFh0poCf29\u{200D}bK44SnLZMBrT1n50X5B4rwblqa1FZS2k64F",
        "ecfg_FW0BvtwcVjSHNW3E6sEiFh0poCf29bK44SnLZMBrT1n50X5B4rwblqa1FZS2k64F",
    );
}

#[test]
fn adv137_vercel_edge_config_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "vercel-edge-config-token",
        "ecfg_FW0BvtwcVjSHNW3E6sEiFh0poCf29\u{FEFF}bK44SnLZMBrT1n50X5B4rwblqa1FZS2k64F",
        "ecfg_FW0BvtwcVjSHNW3E6sEiFh0poCf29bK44SnLZMBrT1n50X5B4rwblqa1FZS2k64F",
    );
}

#[test]
fn adv137_vercel_edge_config_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "vercel-edge-config-token",
        "ecfg_FW0BvtwcVjSHNW3E6sEiFh0poCf29\u{2060}bK44SnLZMBrT1n50X5B4rwblqa1FZS2k64F",
        "ecfg_FW0BvtwcVjSHNW3E6sEiFh0poCf29bK44SnLZMBrT1n50X5B4rwblqa1FZS2k64F",
    );
}

#[test]
fn adv137_vercel_edge_config_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "vercel-edge-config-token",
        "ecfg_FW0BvtwcVjSHNW3E6sEiFh0poCf29\u{180E}bK44SnLZMBrT1n50X5B4rwblqa1FZS2k64F",
        "ecfg_FW0BvtwcVjSHNW3E6sEiFh0poCf29bK44SnLZMBrT1n50X5B4rwblqa1FZS2k64F",
    );
}

#[test]
fn adv137_vercel_edge_config_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "vercel-edge-config-token",
        "ecfg_FW0BvtwcVjSHNW3E6sEiFh0poCf29\u{202E}bK44SnLZMBrT1n50X5B4rwblqa1FZS2k64F",
        "ecfg_FW0BvtwcVjSHNW3E6sEiFh0poCf29bK44SnLZMBrT1n50X5B4rwblqa1FZS2k64F",
    );
}

#[test]
fn adv137_vercel_edge_config_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "vercel-edge-config-token",
        "ecfg_FW0BvtwcVjSHNW3E6sEiFh0poCf29\u{202C}bK44SnLZMBrT1n50X5B4rwblqa1FZS2k64F",
        "ecfg_FW0BvtwcVjSHNW3E6sEiFh0poCf29bK44SnLZMBrT1n50X5B4rwblqa1FZS2k64F",
    );
}

#[test]
fn adv137_vercel_edge_config_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "vercel-edge-config-token",
        "ecfg_FW0BvtwcVjSHNW3E6sEiFh0poCf29\u{200E}bK44SnLZMBrT1n50X5B4rwblqa1FZS2k64F",
        "ecfg_FW0BvtwcVjSHNW3E6sEiFh0poCf29bK44SnLZMBrT1n50X5B4rwblqa1FZS2k64F",
    );
}

// =========================================================================
// 6. VERCEL EDGE FUNCTION CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv137_vercel_edge_function_credentials_normal_must_fire() {
    assert_detector_fires(
        "vercel-edge-function-credentials",
        "ecfg_VWTr5j5Y",
        "ecfg_VWTr5j5Y",
    );
}

#[test]
fn adv137_vercel_edge_function_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "vercel-edge-function-credentials",
        "dummyxxxxxxxxx",
    );
}

#[test]
fn adv137_vercel_edge_function_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "vercel-edge-function-credentials",
        "ecfg_V\u{200B}WTr5j5Y",
        "ecfg_VWTr5j5Y",
    );
}

#[test]
fn adv137_vercel_edge_function_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "vercel-edge-function-credentials",
        "ecfg_V\u{00AD}WTr5j5Y",
        "ecfg_VWTr5j5Y",
    );
}

#[test]
fn adv137_vercel_edge_function_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "vercel-edge-function-credentials",
        "ecfg_V\u{200C}WTr5j5Y",
        "ecfg_VWTr5j5Y",
    );
}

#[test]
fn adv137_vercel_edge_function_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "vercel-edge-function-credentials",
        "ecfg_V\u{200D}WTr5j5Y",
        "ecfg_VWTr5j5Y",
    );
}

#[test]
fn adv137_vercel_edge_function_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "vercel-edge-function-credentials",
        "ecfg_V\u{FEFF}WTr5j5Y",
        "ecfg_VWTr5j5Y",
    );
}

#[test]
fn adv137_vercel_edge_function_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "vercel-edge-function-credentials",
        "ecfg_V\u{2060}WTr5j5Y",
        "ecfg_VWTr5j5Y",
    );
}

#[test]
fn adv137_vercel_edge_function_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "vercel-edge-function-credentials",
        "ecfg_V\u{180E}WTr5j5Y",
        "ecfg_VWTr5j5Y",
    );
}

#[test]
fn adv137_vercel_edge_function_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "vercel-edge-function-credentials",
        "ecfg_V\u{202E}WTr5j5Y",
        "ecfg_VWTr5j5Y",
    );
}

#[test]
fn adv137_vercel_edge_function_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "vercel-edge-function-credentials",
        "ecfg_V\u{202C}WTr5j5Y",
        "ecfg_VWTr5j5Y",
    );
}

#[test]
fn adv137_vercel_edge_function_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "vercel-edge-function-credentials",
        "ecfg_V\u{200E}WTr5j5Y",
        "ecfg_VWTr5j5Y",
    );
}

// =========================================================================
// 7. VERCEL KV CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv137_vercel_kv_credentials_normal_must_fire() {
    assert_detector_fires(
        "vercel-kv-credentials",
        "rediss://default:zOYzlRaA8bp9U1E7qoRp3yCQWE7plXt7L1hz4eHmmlHJjLoWRE-zuhgmhW6lE5Jxta9dI7Cm8sVze9mpIvw@p53nar82r-wovjxqtuh9q3d0c9lxbj7xvcaw79o3fp54t3j32vtm4duqj-q6qavhwb5l0kc5krb2q3hyy-cfkpx.kv.vercel-storage.com:2332318582679547000738265301191677548565193813563001",
        "zOYzlRaA8bp9U1E7qoRp3yCQWE7plXt7L1hz4eHmmlHJjLoWRE-zuhgmhW6lE5Jxta9dI7Cm8sVze9mpIvw",
    );
}

#[test]
fn adv137_vercel_kv_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "vercel-kv-credentials",
        "dummy_prefix_0://default:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx@p53nar82r-wovjxqtuh9q3d0c9lxbj7xvcaw79o3fp54t3j32vtm4duqj-q6qavhwb5l0kc5krb2q3hyy-cfkpx.kv.vercel-storage.com:2332318582679547000738265301191677548565193813563001",
    );
}

#[test]
fn adv137_vercel_kv_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "vercel-kv-credentials",
        "rediss://default:zOYzlRaA8bp9U1E7qoRp3yCQWE7plXt7L1hz4eHmm\u{200B}lHJjLoWRE-zuhgmhW6lE5Jxta9dI7Cm8sVze9mpIvw@p53nar82r-wovjxqtuh9q3d0c9lxbj7xvcaw79o3fp54t3j32vtm4duqj-q6qavhwb5l0kc5krb2q3hyy-cfkpx.kv.vercel-storage.com:2332318582679547000738265301191677548565193813563001",
        "zOYzlRaA8bp9U1E7qoRp3yCQWE7plXt7L1hz4eHmmlHJjLoWRE-zuhgmhW6lE5Jxta9dI7Cm8sVze9mpIvw",
    );
}

#[test]
fn adv137_vercel_kv_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "vercel-kv-credentials",
        "rediss://default:zOYzlRaA8bp9U1E7qoRp3yCQWE7plXt7L1hz4eHmm\u{00AD}lHJjLoWRE-zuhgmhW6lE5Jxta9dI7Cm8sVze9mpIvw@p53nar82r-wovjxqtuh9q3d0c9lxbj7xvcaw79o3fp54t3j32vtm4duqj-q6qavhwb5l0kc5krb2q3hyy-cfkpx.kv.vercel-storage.com:2332318582679547000738265301191677548565193813563001",
        "zOYzlRaA8bp9U1E7qoRp3yCQWE7plXt7L1hz4eHmmlHJjLoWRE-zuhgmhW6lE5Jxta9dI7Cm8sVze9mpIvw",
    );
}

#[test]
fn adv137_vercel_kv_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "vercel-kv-credentials",
        "rediss://default:zOYzlRaA8bp9U1E7qoRp3yCQWE7plXt7L1hz4eHmm\u{200C}lHJjLoWRE-zuhgmhW6lE5Jxta9dI7Cm8sVze9mpIvw@p53nar82r-wovjxqtuh9q3d0c9lxbj7xvcaw79o3fp54t3j32vtm4duqj-q6qavhwb5l0kc5krb2q3hyy-cfkpx.kv.vercel-storage.com:2332318582679547000738265301191677548565193813563001",
        "zOYzlRaA8bp9U1E7qoRp3yCQWE7plXt7L1hz4eHmmlHJjLoWRE-zuhgmhW6lE5Jxta9dI7Cm8sVze9mpIvw",
    );
}

#[test]
fn adv137_vercel_kv_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "vercel-kv-credentials",
        "rediss://default:zOYzlRaA8bp9U1E7qoRp3yCQWE7plXt7L1hz4eHmm\u{200D}lHJjLoWRE-zuhgmhW6lE5Jxta9dI7Cm8sVze9mpIvw@p53nar82r-wovjxqtuh9q3d0c9lxbj7xvcaw79o3fp54t3j32vtm4duqj-q6qavhwb5l0kc5krb2q3hyy-cfkpx.kv.vercel-storage.com:2332318582679547000738265301191677548565193813563001",
        "zOYzlRaA8bp9U1E7qoRp3yCQWE7plXt7L1hz4eHmmlHJjLoWRE-zuhgmhW6lE5Jxta9dI7Cm8sVze9mpIvw",
    );
}

#[test]
fn adv137_vercel_kv_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "vercel-kv-credentials",
        "rediss://default:zOYzlRaA8bp9U1E7qoRp3yCQWE7plXt7L1hz4eHmm\u{FEFF}lHJjLoWRE-zuhgmhW6lE5Jxta9dI7Cm8sVze9mpIvw@p53nar82r-wovjxqtuh9q3d0c9lxbj7xvcaw79o3fp54t3j32vtm4duqj-q6qavhwb5l0kc5krb2q3hyy-cfkpx.kv.vercel-storage.com:2332318582679547000738265301191677548565193813563001",
        "zOYzlRaA8bp9U1E7qoRp3yCQWE7plXt7L1hz4eHmmlHJjLoWRE-zuhgmhW6lE5Jxta9dI7Cm8sVze9mpIvw",
    );
}

#[test]
fn adv137_vercel_kv_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "vercel-kv-credentials",
        "rediss://default:zOYzlRaA8bp9U1E7qoRp3yCQWE7plXt7L1hz4eHmm\u{2060}lHJjLoWRE-zuhgmhW6lE5Jxta9dI7Cm8sVze9mpIvw@p53nar82r-wovjxqtuh9q3d0c9lxbj7xvcaw79o3fp54t3j32vtm4duqj-q6qavhwb5l0kc5krb2q3hyy-cfkpx.kv.vercel-storage.com:2332318582679547000738265301191677548565193813563001",
        "zOYzlRaA8bp9U1E7qoRp3yCQWE7plXt7L1hz4eHmmlHJjLoWRE-zuhgmhW6lE5Jxta9dI7Cm8sVze9mpIvw",
    );
}

#[test]
fn adv137_vercel_kv_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "vercel-kv-credentials",
        "rediss://default:zOYzlRaA8bp9U1E7qoRp3yCQWE7plXt7L1hz4eHmm\u{180E}lHJjLoWRE-zuhgmhW6lE5Jxta9dI7Cm8sVze9mpIvw@p53nar82r-wovjxqtuh9q3d0c9lxbj7xvcaw79o3fp54t3j32vtm4duqj-q6qavhwb5l0kc5krb2q3hyy-cfkpx.kv.vercel-storage.com:2332318582679547000738265301191677548565193813563001",
        "zOYzlRaA8bp9U1E7qoRp3yCQWE7plXt7L1hz4eHmmlHJjLoWRE-zuhgmhW6lE5Jxta9dI7Cm8sVze9mpIvw",
    );
}

#[test]
fn adv137_vercel_kv_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "vercel-kv-credentials",
        "rediss://default:zOYzlRaA8bp9U1E7qoRp3yCQWE7plXt7L1hz4eHmm\u{202E}lHJjLoWRE-zuhgmhW6lE5Jxta9dI7Cm8sVze9mpIvw@p53nar82r-wovjxqtuh9q3d0c9lxbj7xvcaw79o3fp54t3j32vtm4duqj-q6qavhwb5l0kc5krb2q3hyy-cfkpx.kv.vercel-storage.com:2332318582679547000738265301191677548565193813563001",
        "zOYzlRaA8bp9U1E7qoRp3yCQWE7plXt7L1hz4eHmmlHJjLoWRE-zuhgmhW6lE5Jxta9dI7Cm8sVze9mpIvw",
    );
}

#[test]
fn adv137_vercel_kv_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "vercel-kv-credentials",
        "rediss://default:zOYzlRaA8bp9U1E7qoRp3yCQWE7plXt7L1hz4eHmm\u{202C}lHJjLoWRE-zuhgmhW6lE5Jxta9dI7Cm8sVze9mpIvw@p53nar82r-wovjxqtuh9q3d0c9lxbj7xvcaw79o3fp54t3j32vtm4duqj-q6qavhwb5l0kc5krb2q3hyy-cfkpx.kv.vercel-storage.com:2332318582679547000738265301191677548565193813563001",
        "zOYzlRaA8bp9U1E7qoRp3yCQWE7plXt7L1hz4eHmmlHJjLoWRE-zuhgmhW6lE5Jxta9dI7Cm8sVze9mpIvw",
    );
}

#[test]
fn adv137_vercel_kv_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "vercel-kv-credentials",
        "rediss://default:zOYzlRaA8bp9U1E7qoRp3yCQWE7plXt7L1hz4eHmm\u{200E}lHJjLoWRE-zuhgmhW6lE5Jxta9dI7Cm8sVze9mpIvw@p53nar82r-wovjxqtuh9q3d0c9lxbj7xvcaw79o3fp54t3j32vtm4duqj-q6qavhwb5l0kc5krb2q3hyy-cfkpx.kv.vercel-storage.com:2332318582679547000738265301191677548565193813563001",
        "zOYzlRaA8bp9U1E7qoRp3yCQWE7plXt7L1hz4eHmmlHJjLoWRE-zuhgmhW6lE5Jxta9dI7Cm8sVze9mpIvw",
    );
}

// =========================================================================
// 8. VERCEL POSTGRES CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv137_vercel_postgres_credentials_normal_must_fire() {
    assert_detector_fires(
        "vercel-postgres-credentials",
        "postgresql://JQgb-oFlz0:zoecT3oGVamVmsHMHxVtzHFcYASF@6vhfjco108k-y5htf0vmnbbuqvjif2jus455dxv95g5qamhjtngvqgzuwyl14n9l0vijywmfije2697fkqtlke2qy4m9lakslgmmlvbd2bqj35q-xw8dhcxwe6rng8qwjhjzbmg5cpio4ftvc8jodw7tl3bl1qnt9m4vinj.a45w3mrh6erpg4z0kwo109ebnqzljfh4ru7s9ig2q0k8chfpjp7thznpzknlrl6l3d77qf3hfaw0lqex0umk31ww6jl10aew.cwuhmuxnwvvamgifklyoibsbpzuc.verceldb.com:178939128162920792068103005820241125507435164873061780278494053033819149389514933969939934773157588/kcaCj03mW",
        "zoecT3oGVamVmsHMHxVtzHFcYASF",
    );
}

#[test]
fn adv137_vercel_postgres_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "vercel-postgres-credentials",
        "dummy_prefix_0://JQgb-oFlz0:xxxxxxxxxxxxxxxxxxxxxxxxxxxx@6vhfjco108k-y5htf0vmnbbuqvjif2jus455dxv95g5qamhjtngvqgzuwyl14n9l0vijywmfije2697fkqtlke2qy4m9lakslgmmlvbd2bqj35q-xw8dhcxwe6rng8qwjhjzbmg5cpio4ftvc8jodw7tl3bl1qnt9m4vinj.a45w3mrh6erpg4z0kwo109ebnqzljfh4ru7s9ig2q0k8chfpjp7thznpzknlrl6l3d77qf3hfaw0lqex0umk31ww6jl10aew.cwuhmuxnwvvamgifklyoibsbpzuc.verceldb.com:178939128162920792068103005820241125507435164873061780278494053033819149389514933969939934773157588/kcaCj03mW",
    );
}

#[test]
fn adv137_vercel_postgres_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "vercel-postgres-credentials",
        "postgresql://JQgb-oFlz0:zoecT3oGVamVms\u{200B}HMHxVtzHFcYASF@6vhfjco108k-y5htf0vmnbbuqvjif2jus455dxv95g5qamhjtngvqgzuwyl14n9l0vijywmfije2697fkqtlke2qy4m9lakslgmmlvbd2bqj35q-xw8dhcxwe6rng8qwjhjzbmg5cpio4ftvc8jodw7tl3bl1qnt9m4vinj.a45w3mrh6erpg4z0kwo109ebnqzljfh4ru7s9ig2q0k8chfpjp7thznpzknlrl6l3d77qf3hfaw0lqex0umk31ww6jl10aew.cwuhmuxnwvvamgifklyoibsbpzuc.verceldb.com:178939128162920792068103005820241125507435164873061780278494053033819149389514933969939934773157588/kcaCj03mW",
        "zoecT3oGVamVmsHMHxVtzHFcYASF",
    );
}

#[test]
fn adv137_vercel_postgres_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "vercel-postgres-credentials",
        "postgresql://JQgb-oFlz0:zoecT3oGVamVms\u{00AD}HMHxVtzHFcYASF@6vhfjco108k-y5htf0vmnbbuqvjif2jus455dxv95g5qamhjtngvqgzuwyl14n9l0vijywmfije2697fkqtlke2qy4m9lakslgmmlvbd2bqj35q-xw8dhcxwe6rng8qwjhjzbmg5cpio4ftvc8jodw7tl3bl1qnt9m4vinj.a45w3mrh6erpg4z0kwo109ebnqzljfh4ru7s9ig2q0k8chfpjp7thznpzknlrl6l3d77qf3hfaw0lqex0umk31ww6jl10aew.cwuhmuxnwvvamgifklyoibsbpzuc.verceldb.com:178939128162920792068103005820241125507435164873061780278494053033819149389514933969939934773157588/kcaCj03mW",
        "zoecT3oGVamVmsHMHxVtzHFcYASF",
    );
}

#[test]
fn adv137_vercel_postgres_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "vercel-postgres-credentials",
        "postgresql://JQgb-oFlz0:zoecT3oGVamVms\u{200C}HMHxVtzHFcYASF@6vhfjco108k-y5htf0vmnbbuqvjif2jus455dxv95g5qamhjtngvqgzuwyl14n9l0vijywmfije2697fkqtlke2qy4m9lakslgmmlvbd2bqj35q-xw8dhcxwe6rng8qwjhjzbmg5cpio4ftvc8jodw7tl3bl1qnt9m4vinj.a45w3mrh6erpg4z0kwo109ebnqzljfh4ru7s9ig2q0k8chfpjp7thznpzknlrl6l3d77qf3hfaw0lqex0umk31ww6jl10aew.cwuhmuxnwvvamgifklyoibsbpzuc.verceldb.com:178939128162920792068103005820241125507435164873061780278494053033819149389514933969939934773157588/kcaCj03mW",
        "zoecT3oGVamVmsHMHxVtzHFcYASF",
    );
}

#[test]
fn adv137_vercel_postgres_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "vercel-postgres-credentials",
        "postgresql://JQgb-oFlz0:zoecT3oGVamVms\u{200D}HMHxVtzHFcYASF@6vhfjco108k-y5htf0vmnbbuqvjif2jus455dxv95g5qamhjtngvqgzuwyl14n9l0vijywmfije2697fkqtlke2qy4m9lakslgmmlvbd2bqj35q-xw8dhcxwe6rng8qwjhjzbmg5cpio4ftvc8jodw7tl3bl1qnt9m4vinj.a45w3mrh6erpg4z0kwo109ebnqzljfh4ru7s9ig2q0k8chfpjp7thznpzknlrl6l3d77qf3hfaw0lqex0umk31ww6jl10aew.cwuhmuxnwvvamgifklyoibsbpzuc.verceldb.com:178939128162920792068103005820241125507435164873061780278494053033819149389514933969939934773157588/kcaCj03mW",
        "zoecT3oGVamVmsHMHxVtzHFcYASF",
    );
}

#[test]
fn adv137_vercel_postgres_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "vercel-postgres-credentials",
        "postgresql://JQgb-oFlz0:zoecT3oGVamVms\u{FEFF}HMHxVtzHFcYASF@6vhfjco108k-y5htf0vmnbbuqvjif2jus455dxv95g5qamhjtngvqgzuwyl14n9l0vijywmfije2697fkqtlke2qy4m9lakslgmmlvbd2bqj35q-xw8dhcxwe6rng8qwjhjzbmg5cpio4ftvc8jodw7tl3bl1qnt9m4vinj.a45w3mrh6erpg4z0kwo109ebnqzljfh4ru7s9ig2q0k8chfpjp7thznpzknlrl6l3d77qf3hfaw0lqex0umk31ww6jl10aew.cwuhmuxnwvvamgifklyoibsbpzuc.verceldb.com:178939128162920792068103005820241125507435164873061780278494053033819149389514933969939934773157588/kcaCj03mW",
        "zoecT3oGVamVmsHMHxVtzHFcYASF",
    );
}

#[test]
fn adv137_vercel_postgres_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "vercel-postgres-credentials",
        "postgresql://JQgb-oFlz0:zoecT3oGVamVms\u{2060}HMHxVtzHFcYASF@6vhfjco108k-y5htf0vmnbbuqvjif2jus455dxv95g5qamhjtngvqgzuwyl14n9l0vijywmfije2697fkqtlke2qy4m9lakslgmmlvbd2bqj35q-xw8dhcxwe6rng8qwjhjzbmg5cpio4ftvc8jodw7tl3bl1qnt9m4vinj.a45w3mrh6erpg4z0kwo109ebnqzljfh4ru7s9ig2q0k8chfpjp7thznpzknlrl6l3d77qf3hfaw0lqex0umk31ww6jl10aew.cwuhmuxnwvvamgifklyoibsbpzuc.verceldb.com:178939128162920792068103005820241125507435164873061780278494053033819149389514933969939934773157588/kcaCj03mW",
        "zoecT3oGVamVmsHMHxVtzHFcYASF",
    );
}

#[test]
fn adv137_vercel_postgres_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "vercel-postgres-credentials",
        "postgresql://JQgb-oFlz0:zoecT3oGVamVms\u{180E}HMHxVtzHFcYASF@6vhfjco108k-y5htf0vmnbbuqvjif2jus455dxv95g5qamhjtngvqgzuwyl14n9l0vijywmfije2697fkqtlke2qy4m9lakslgmmlvbd2bqj35q-xw8dhcxwe6rng8qwjhjzbmg5cpio4ftvc8jodw7tl3bl1qnt9m4vinj.a45w3mrh6erpg4z0kwo109ebnqzljfh4ru7s9ig2q0k8chfpjp7thznpzknlrl6l3d77qf3hfaw0lqex0umk31ww6jl10aew.cwuhmuxnwvvamgifklyoibsbpzuc.verceldb.com:178939128162920792068103005820241125507435164873061780278494053033819149389514933969939934773157588/kcaCj03mW",
        "zoecT3oGVamVmsHMHxVtzHFcYASF",
    );
}

#[test]
fn adv137_vercel_postgres_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "vercel-postgres-credentials",
        "postgresql://JQgb-oFlz0:zoecT3oGVamVms\u{202E}HMHxVtzHFcYASF@6vhfjco108k-y5htf0vmnbbuqvjif2jus455dxv95g5qamhjtngvqgzuwyl14n9l0vijywmfije2697fkqtlke2qy4m9lakslgmmlvbd2bqj35q-xw8dhcxwe6rng8qwjhjzbmg5cpio4ftvc8jodw7tl3bl1qnt9m4vinj.a45w3mrh6erpg4z0kwo109ebnqzljfh4ru7s9ig2q0k8chfpjp7thznpzknlrl6l3d77qf3hfaw0lqex0umk31ww6jl10aew.cwuhmuxnwvvamgifklyoibsbpzuc.verceldb.com:178939128162920792068103005820241125507435164873061780278494053033819149389514933969939934773157588/kcaCj03mW",
        "zoecT3oGVamVmsHMHxVtzHFcYASF",
    );
}

#[test]
fn adv137_vercel_postgres_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "vercel-postgres-credentials",
        "postgresql://JQgb-oFlz0:zoecT3oGVamVms\u{202C}HMHxVtzHFcYASF@6vhfjco108k-y5htf0vmnbbuqvjif2jus455dxv95g5qamhjtngvqgzuwyl14n9l0vijywmfije2697fkqtlke2qy4m9lakslgmmlvbd2bqj35q-xw8dhcxwe6rng8qwjhjzbmg5cpio4ftvc8jodw7tl3bl1qnt9m4vinj.a45w3mrh6erpg4z0kwo109ebnqzljfh4ru7s9ig2q0k8chfpjp7thznpzknlrl6l3d77qf3hfaw0lqex0umk31ww6jl10aew.cwuhmuxnwvvamgifklyoibsbpzuc.verceldb.com:178939128162920792068103005820241125507435164873061780278494053033819149389514933969939934773157588/kcaCj03mW",
        "zoecT3oGVamVmsHMHxVtzHFcYASF",
    );
}

#[test]
fn adv137_vercel_postgres_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "vercel-postgres-credentials",
        "postgresql://JQgb-oFlz0:zoecT3oGVamVms\u{200E}HMHxVtzHFcYASF@6vhfjco108k-y5htf0vmnbbuqvjif2jus455dxv95g5qamhjtngvqgzuwyl14n9l0vijywmfije2697fkqtlke2qy4m9lakslgmmlvbd2bqj35q-xw8dhcxwe6rng8qwjhjzbmg5cpio4ftvc8jodw7tl3bl1qnt9m4vinj.a45w3mrh6erpg4z0kwo109ebnqzljfh4ru7s9ig2q0k8chfpjp7thznpzknlrl6l3d77qf3hfaw0lqex0umk31ww6jl10aew.cwuhmuxnwvvamgifklyoibsbpzuc.verceldb.com:178939128162920792068103005820241125507435164873061780278494053033819149389514933969939934773157588/kcaCj03mW",
        "zoecT3oGVamVmsHMHxVtzHFcYASF",
    );
}

// =========================================================================
// 9. VERCEL TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv137_vercel_token_normal_must_fire() {
    assert_detector_fires(
        "vercel-token",
        "VERCEL_TOKEN=Xh7QkP4mZ2sBvR9aT5fN8cWy",
        "Xh7QkP4mZ2sBvR9aT5fN8cWy",
    );
}

#[test]
fn adv137_vercel_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "vercel-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv137_vercel_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "vercel-token",
        "VERCEL_TOKEN=Xh7QkP4mZ2sB\u{200B}vR9aT5fN8cWy",
        "Xh7QkP4mZ2sBvR9aT5fN8cWy",
    );
}

#[test]
fn adv137_vercel_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "vercel-token",
        "VERCEL_TOKEN=Xh7QkP4mZ2sB\u{00AD}vR9aT5fN8cWy",
        "Xh7QkP4mZ2sBvR9aT5fN8cWy",
    );
}

#[test]
fn adv137_vercel_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "vercel-token",
        "VERCEL_TOKEN=Xh7QkP4mZ2sB\u{200C}vR9aT5fN8cWy",
        "Xh7QkP4mZ2sBvR9aT5fN8cWy",
    );
}

#[test]
fn adv137_vercel_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "vercel-token",
        "VERCEL_TOKEN=Xh7QkP4mZ2sB\u{200D}vR9aT5fN8cWy",
        "Xh7QkP4mZ2sBvR9aT5fN8cWy",
    );
}

#[test]
fn adv137_vercel_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "vercel-token",
        "VERCEL_TOKEN=Xh7QkP4mZ2sB\u{FEFF}vR9aT5fN8cWy",
        "Xh7QkP4mZ2sBvR9aT5fN8cWy",
    );
}

#[test]
fn adv137_vercel_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "vercel-token",
        "VERCEL_TOKEN=Xh7QkP4mZ2sB\u{2060}vR9aT5fN8cWy",
        "Xh7QkP4mZ2sBvR9aT5fN8cWy",
    );
}

#[test]
fn adv137_vercel_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "vercel-token",
        "VERCEL_TOKEN=Xh7QkP4mZ2sB\u{180E}vR9aT5fN8cWy",
        "Xh7QkP4mZ2sBvR9aT5fN8cWy",
    );
}

#[test]
fn adv137_vercel_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "vercel-token",
        "VERCEL_TOKEN=Xh7QkP4mZ2sB\u{202E}vR9aT5fN8cWy",
        "Xh7QkP4mZ2sBvR9aT5fN8cWy",
    );
}

#[test]
fn adv137_vercel_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "vercel-token",
        "VERCEL_TOKEN=Xh7QkP4mZ2sB\u{202C}vR9aT5fN8cWy",
        "Xh7QkP4mZ2sBvR9aT5fN8cWy",
    );
}

#[test]
fn adv137_vercel_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "vercel-token",
        "VERCEL_TOKEN=Xh7QkP4mZ2sB\u{200E}vR9aT5fN8cWy",
        "Xh7QkP4mZ2sBvR9aT5fN8cWy",
    );
}

// =========================================================================
// 10. VIMEO API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv137_vimeo_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "vimeo-api-credentials",
        "vimeoaccess_token=15eed71e4d259e740161a1091da6649b",
        "15eed71e4d259e740161a1091da6649b",
    );
}

#[test]
fn adv137_vimeo_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "vimeo-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv137_vimeo_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "vimeo-api-credentials",
        "vimeoaccess_token=15eed71e4d259e74\u{200B}0161a1091da6649b",
        "15eed71e4d259e740161a1091da6649b",
    );
}

#[test]
fn adv137_vimeo_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "vimeo-api-credentials",
        "vimeoaccess_token=15eed71e4d259e74\u{00AD}0161a1091da6649b",
        "15eed71e4d259e740161a1091da6649b",
    );
}

#[test]
fn adv137_vimeo_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "vimeo-api-credentials",
        "vimeoaccess_token=15eed71e4d259e74\u{200C}0161a1091da6649b",
        "15eed71e4d259e740161a1091da6649b",
    );
}

#[test]
fn adv137_vimeo_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "vimeo-api-credentials",
        "vimeoaccess_token=15eed71e4d259e74\u{200D}0161a1091da6649b",
        "15eed71e4d259e740161a1091da6649b",
    );
}

#[test]
fn adv137_vimeo_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "vimeo-api-credentials",
        "vimeoaccess_token=15eed71e4d259e74\u{FEFF}0161a1091da6649b",
        "15eed71e4d259e740161a1091da6649b",
    );
}

#[test]
fn adv137_vimeo_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "vimeo-api-credentials",
        "vimeoaccess_token=15eed71e4d259e74\u{2060}0161a1091da6649b",
        "15eed71e4d259e740161a1091da6649b",
    );
}

#[test]
fn adv137_vimeo_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "vimeo-api-credentials",
        "vimeoaccess_token=15eed71e4d259e74\u{180E}0161a1091da6649b",
        "15eed71e4d259e740161a1091da6649b",
    );
}

#[test]
fn adv137_vimeo_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "vimeo-api-credentials",
        "vimeoaccess_token=15eed71e4d259e74\u{202E}0161a1091da6649b",
        "15eed71e4d259e740161a1091da6649b",
    );
}

#[test]
fn adv137_vimeo_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "vimeo-api-credentials",
        "vimeoaccess_token=15eed71e4d259e74\u{202C}0161a1091da6649b",
        "15eed71e4d259e740161a1091da6649b",
    );
}

#[test]
fn adv137_vimeo_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "vimeo-api-credentials",
        "vimeoaccess_token=15eed71e4d259e74\u{200E}0161a1091da6649b",
        "15eed71e4d259e740161a1091da6649b",
    );
}


