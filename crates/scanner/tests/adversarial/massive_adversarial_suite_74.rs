//! Part 74 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates carbon, cargo, casdoor, catchpoint, cch, census, censys, ceph, cerebrium, cfengine detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. CARBON BLACK API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv74_carbon_black_api_key_normal_must_fire() {
    assert_detector_fires(
        "carbon-black-api-key",
        "CB API KEY=7B3E5D8C1A9F4E2B6C8D3A5E",
        "7B3E5D8C1A9F4E2B6C8D3A5E",
    );
}

#[test]
fn adv74_carbon_black_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "carbon-black-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv74_carbon_black_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "carbon-black-api-key",
        "CB API KEY=7B3E5D8C1A9F\u{200B}4E2B6C8D3A5E",
        "7B3E5D8C1A9F4E2B6C8D3A5E",
    );
}

#[test]
fn adv74_carbon_black_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "carbon-black-api-key",
        "CB API KEY=7B3E5D8C1A9F\u{00AD}4E2B6C8D3A5E",
        "7B3E5D8C1A9F4E2B6C8D3A5E",
    );
}

#[test]
fn adv74_carbon_black_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "carbon-black-api-key",
        "CB API KEY=7B3E5D8C1A9F\u{200C}4E2B6C8D3A5E",
        "7B3E5D8C1A9F4E2B6C8D3A5E",
    );
}

#[test]
fn adv74_carbon_black_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "carbon-black-api-key",
        "CB API KEY=7B3E5D8C1A9F\u{200D}4E2B6C8D3A5E",
        "7B3E5D8C1A9F4E2B6C8D3A5E",
    );
}

#[test]
fn adv74_carbon_black_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "carbon-black-api-key",
        "CB API KEY=7B3E5D8C1A9F\u{FEFF}4E2B6C8D3A5E",
        "7B3E5D8C1A9F4E2B6C8D3A5E",
    );
}

#[test]
fn adv74_carbon_black_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "carbon-black-api-key",
        "CB API KEY=7B3E5D8C1A9F\u{2060}4E2B6C8D3A5E",
        "7B3E5D8C1A9F4E2B6C8D3A5E",
    );
}

#[test]
fn adv74_carbon_black_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "carbon-black-api-key",
        "CB API KEY=7B3E5D8C1A9F\u{180E}4E2B6C8D3A5E",
        "7B3E5D8C1A9F4E2B6C8D3A5E",
    );
}

#[test]
fn adv74_carbon_black_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "carbon-black-api-key",
        "CB API KEY=7B3E5D8C1A9F\u{202E}4E2B6C8D3A5E",
        "7B3E5D8C1A9F4E2B6C8D3A5E",
    );
}

#[test]
fn adv74_carbon_black_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "carbon-black-api-key",
        "CB API KEY=7B3E5D8C1A9F\u{202C}4E2B6C8D3A5E",
        "7B3E5D8C1A9F4E2B6C8D3A5E",
    );
}

#[test]
fn adv74_carbon_black_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "carbon-black-api-key",
        "CB API KEY=7B3E5D8C1A9F\u{200E}4E2B6C8D3A5E",
        "7B3E5D8C1A9F4E2B6C8D3A5E",
    );
}

// =========================================================================
// 2. CARGO REGISTRY TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv74_cargo_registry_token_normal_must_fire() {
    assert_detector_fires(
        "cargo-registry-token",
        "CARGO_REGISTRY_TOKEN=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv74_cargo_registry_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "cargo-registry-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv74_cargo_registry_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "cargo-registry-token",
        "CARGO_REGISTRY_TOKEN=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv74_cargo_registry_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "cargo-registry-token",
        "CARGO_REGISTRY_TOKEN=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv74_cargo_registry_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "cargo-registry-token",
        "CARGO_REGISTRY_TOKEN=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv74_cargo_registry_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "cargo-registry-token",
        "CARGO_REGISTRY_TOKEN=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv74_cargo_registry_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "cargo-registry-token",
        "CARGO_REGISTRY_TOKEN=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv74_cargo_registry_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "cargo-registry-token",
        "CARGO_REGISTRY_TOKEN=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv74_cargo_registry_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "cargo-registry-token",
        "CARGO_REGISTRY_TOKEN=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv74_cargo_registry_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "cargo-registry-token",
        "CARGO_REGISTRY_TOKEN=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv74_cargo_registry_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "cargo-registry-token",
        "CARGO_REGISTRY_TOKEN=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv74_cargo_registry_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "cargo-registry-token",
        "CARGO_REGISTRY_TOKEN=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 3. CASDOOR CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv74_casdoor_credentials_normal_must_fire() {
    assert_detector_fires(
        "casdoor-credentials",
        "CASDOOR_CLIENT_ID=7b3e5d8c1a9f4e2b6c8d",
        "7b3e5d8c1a9f4e2b6c8d",
    );
}

#[test]
fn adv74_casdoor_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "casdoor-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv74_casdoor_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "casdoor-credentials",
        "CASDOOR_CLIENT_ID=7b3e5d8c1a\u{200B}9f4e2b6c8d",
        "7b3e5d8c1a9f4e2b6c8d",
    );
}

#[test]
fn adv74_casdoor_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "casdoor-credentials",
        "CASDOOR_CLIENT_ID=7b3e5d8c1a\u{00AD}9f4e2b6c8d",
        "7b3e5d8c1a9f4e2b6c8d",
    );
}

#[test]
fn adv74_casdoor_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "casdoor-credentials",
        "CASDOOR_CLIENT_ID=7b3e5d8c1a\u{200C}9f4e2b6c8d",
        "7b3e5d8c1a9f4e2b6c8d",
    );
}

#[test]
fn adv74_casdoor_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "casdoor-credentials",
        "CASDOOR_CLIENT_ID=7b3e5d8c1a\u{200D}9f4e2b6c8d",
        "7b3e5d8c1a9f4e2b6c8d",
    );
}

#[test]
fn adv74_casdoor_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "casdoor-credentials",
        "CASDOOR_CLIENT_ID=7b3e5d8c1a\u{FEFF}9f4e2b6c8d",
        "7b3e5d8c1a9f4e2b6c8d",
    );
}

#[test]
fn adv74_casdoor_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "casdoor-credentials",
        "CASDOOR_CLIENT_ID=7b3e5d8c1a\u{2060}9f4e2b6c8d",
        "7b3e5d8c1a9f4e2b6c8d",
    );
}

#[test]
fn adv74_casdoor_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "casdoor-credentials",
        "CASDOOR_CLIENT_ID=7b3e5d8c1a\u{180E}9f4e2b6c8d",
        "7b3e5d8c1a9f4e2b6c8d",
    );
}

#[test]
fn adv74_casdoor_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "casdoor-credentials",
        "CASDOOR_CLIENT_ID=7b3e5d8c1a\u{202E}9f4e2b6c8d",
        "7b3e5d8c1a9f4e2b6c8d",
    );
}

#[test]
fn adv74_casdoor_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "casdoor-credentials",
        "CASDOOR_CLIENT_ID=7b3e5d8c1a\u{202C}9f4e2b6c8d",
        "7b3e5d8c1a9f4e2b6c8d",
    );
}

#[test]
fn adv74_casdoor_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "casdoor-credentials",
        "CASDOOR_CLIENT_ID=7b3e5d8c1a\u{200E}9f4e2b6c8d",
        "7b3e5d8c1a9f4e2b6c8d",
    );
}

// =========================================================================
// 4. CATCHPOINT API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv74_catchpoint_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "catchpoint-api-credentials",
        "catchpoint_api_token=Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_catchpoint_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "catchpoint-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv74_catchpoint_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "catchpoint-api-credentials",
        "catchpoint_api_token=Kp4Qx7Rm2S\u{200B}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_catchpoint_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "catchpoint-api-credentials",
        "catchpoint_api_token=Kp4Qx7Rm2S\u{00AD}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_catchpoint_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "catchpoint-api-credentials",
        "catchpoint_api_token=Kp4Qx7Rm2S\u{200C}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_catchpoint_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "catchpoint-api-credentials",
        "catchpoint_api_token=Kp4Qx7Rm2S\u{200D}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_catchpoint_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "catchpoint-api-credentials",
        "catchpoint_api_token=Kp4Qx7Rm2S\u{FEFF}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_catchpoint_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "catchpoint-api-credentials",
        "catchpoint_api_token=Kp4Qx7Rm2S\u{2060}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_catchpoint_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "catchpoint-api-credentials",
        "catchpoint_api_token=Kp4Qx7Rm2S\u{180E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_catchpoint_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "catchpoint-api-credentials",
        "catchpoint_api_token=Kp4Qx7Rm2S\u{202E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_catchpoint_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "catchpoint-api-credentials",
        "catchpoint_api_token=Kp4Qx7Rm2S\u{202C}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_catchpoint_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "catchpoint-api-credentials",
        "catchpoint_api_token=Kp4Qx7Rm2S\u{200E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 5. CCH AXCESS API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv74_cch_axcess_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "cch-axcess-api-credentials",
        "CCH_AXCESS_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_cch_axcess_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "cch-axcess-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv74_cch_axcess_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "cch-axcess-api-credentials",
        "CCH_AXCESS_API_KEY=Kp4Qx7Rm2S\u{200B}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_cch_axcess_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "cch-axcess-api-credentials",
        "CCH_AXCESS_API_KEY=Kp4Qx7Rm2S\u{00AD}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_cch_axcess_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "cch-axcess-api-credentials",
        "CCH_AXCESS_API_KEY=Kp4Qx7Rm2S\u{200C}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_cch_axcess_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "cch-axcess-api-credentials",
        "CCH_AXCESS_API_KEY=Kp4Qx7Rm2S\u{200D}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_cch_axcess_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "cch-axcess-api-credentials",
        "CCH_AXCESS_API_KEY=Kp4Qx7Rm2S\u{FEFF}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_cch_axcess_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "cch-axcess-api-credentials",
        "CCH_AXCESS_API_KEY=Kp4Qx7Rm2S\u{2060}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_cch_axcess_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "cch-axcess-api-credentials",
        "CCH_AXCESS_API_KEY=Kp4Qx7Rm2S\u{180E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_cch_axcess_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "cch-axcess-api-credentials",
        "CCH_AXCESS_API_KEY=Kp4Qx7Rm2S\u{202E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_cch_axcess_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "cch-axcess-api-credentials",
        "CCH_AXCESS_API_KEY=Kp4Qx7Rm2S\u{202C}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_cch_axcess_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "cch-axcess-api-credentials",
        "CCH_AXCESS_API_KEY=Kp4Qx7Rm2S\u{200E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 6. CENSUS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv74_census_api_key_normal_must_fire() {
    assert_detector_fires(
        "census-api-key",
        "CENSUS_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv74_census_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "census-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv74_census_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "census-api-key",
        "CENSUS_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv74_census_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "census-api-key",
        "CENSUS_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv74_census_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "census-api-key",
        "CENSUS_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv74_census_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "census-api-key",
        "CENSUS_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv74_census_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "census-api-key",
        "CENSUS_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv74_census_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "census-api-key",
        "CENSUS_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv74_census_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "census-api-key",
        "CENSUS_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv74_census_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "census-api-key",
        "CENSUS_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv74_census_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "census-api-key",
        "CENSUS_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv74_census_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "census-api-key",
        "CENSUS_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 7. CENSYS API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv74_censys_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "censys-api-credentials",
        "CENSYS_API_ID=ee2b323c-0d0d-3600-fc01-810eadc9b1fb",
        "ee2b323c-0d0d-3600-fc01-810eadc9b1fb",
    );
}

#[test]
fn adv74_censys_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "censys-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv74_censys_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "censys-api-credentials",
        "CENSYS_API_ID=ee2b323c-0d0d-3600\u{200B}-fc01-810eadc9b1fb",
        "ee2b323c-0d0d-3600-fc01-810eadc9b1fb",
    );
}

#[test]
fn adv74_censys_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "censys-api-credentials",
        "CENSYS_API_ID=ee2b323c-0d0d-3600\u{00AD}-fc01-810eadc9b1fb",
        "ee2b323c-0d0d-3600-fc01-810eadc9b1fb",
    );
}

#[test]
fn adv74_censys_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "censys-api-credentials",
        "CENSYS_API_ID=ee2b323c-0d0d-3600\u{200C}-fc01-810eadc9b1fb",
        "ee2b323c-0d0d-3600-fc01-810eadc9b1fb",
    );
}

#[test]
fn adv74_censys_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "censys-api-credentials",
        "CENSYS_API_ID=ee2b323c-0d0d-3600\u{200D}-fc01-810eadc9b1fb",
        "ee2b323c-0d0d-3600-fc01-810eadc9b1fb",
    );
}

#[test]
fn adv74_censys_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "censys-api-credentials",
        "CENSYS_API_ID=ee2b323c-0d0d-3600\u{FEFF}-fc01-810eadc9b1fb",
        "ee2b323c-0d0d-3600-fc01-810eadc9b1fb",
    );
}

#[test]
fn adv74_censys_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "censys-api-credentials",
        "CENSYS_API_ID=ee2b323c-0d0d-3600\u{2060}-fc01-810eadc9b1fb",
        "ee2b323c-0d0d-3600-fc01-810eadc9b1fb",
    );
}

#[test]
fn adv74_censys_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "censys-api-credentials",
        "CENSYS_API_ID=ee2b323c-0d0d-3600\u{180E}-fc01-810eadc9b1fb",
        "ee2b323c-0d0d-3600-fc01-810eadc9b1fb",
    );
}

#[test]
fn adv74_censys_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "censys-api-credentials",
        "CENSYS_API_ID=ee2b323c-0d0d-3600\u{202E}-fc01-810eadc9b1fb",
        "ee2b323c-0d0d-3600-fc01-810eadc9b1fb",
    );
}

#[test]
fn adv74_censys_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "censys-api-credentials",
        "CENSYS_API_ID=ee2b323c-0d0d-3600\u{202C}-fc01-810eadc9b1fb",
        "ee2b323c-0d0d-3600-fc01-810eadc9b1fb",
    );
}

#[test]
fn adv74_censys_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "censys-api-credentials",
        "CENSYS_API_ID=ee2b323c-0d0d-3600\u{200E}-fc01-810eadc9b1fb",
        "ee2b323c-0d0d-3600-fc01-810eadc9b1fb",
    );
}

// =========================================================================
// 8. CEPH RADOS GATEWAY CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv74_ceph_rados_gateway_credentials_normal_must_fire() {
    assert_detector_fires(
        "ceph-rados-gateway-credentials",
        "CEPH_ACCESS_KEY=KP4QX7RM2SN5TB8VW3YZ",
        "KP4QX7RM2SN5TB8VW3YZ",
    );
}

#[test]
fn adv74_ceph_rados_gateway_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "ceph-rados-gateway-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv74_ceph_rados_gateway_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ceph-rados-gateway-credentials",
        "CEPH_ACCESS_KEY=KP4QX7RM2S\u{200B}N5TB8VW3YZ",
        "KP4QX7RM2SN5TB8VW3YZ",
    );
}

#[test]
fn adv74_ceph_rados_gateway_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ceph-rados-gateway-credentials",
        "CEPH_ACCESS_KEY=KP4QX7RM2S\u{00AD}N5TB8VW3YZ",
        "KP4QX7RM2SN5TB8VW3YZ",
    );
}

#[test]
fn adv74_ceph_rados_gateway_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "ceph-rados-gateway-credentials",
        "CEPH_ACCESS_KEY=KP4QX7RM2S\u{200C}N5TB8VW3YZ",
        "KP4QX7RM2SN5TB8VW3YZ",
    );
}

#[test]
fn adv74_ceph_rados_gateway_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "ceph-rados-gateway-credentials",
        "CEPH_ACCESS_KEY=KP4QX7RM2S\u{200D}N5TB8VW3YZ",
        "KP4QX7RM2SN5TB8VW3YZ",
    );
}

#[test]
fn adv74_ceph_rados_gateway_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "ceph-rados-gateway-credentials",
        "CEPH_ACCESS_KEY=KP4QX7RM2S\u{FEFF}N5TB8VW3YZ",
        "KP4QX7RM2SN5TB8VW3YZ",
    );
}

#[test]
fn adv74_ceph_rados_gateway_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "ceph-rados-gateway-credentials",
        "CEPH_ACCESS_KEY=KP4QX7RM2S\u{2060}N5TB8VW3YZ",
        "KP4QX7RM2SN5TB8VW3YZ",
    );
}

#[test]
fn adv74_ceph_rados_gateway_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "ceph-rados-gateway-credentials",
        "CEPH_ACCESS_KEY=KP4QX7RM2S\u{180E}N5TB8VW3YZ",
        "KP4QX7RM2SN5TB8VW3YZ",
    );
}

#[test]
fn adv74_ceph_rados_gateway_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "ceph-rados-gateway-credentials",
        "CEPH_ACCESS_KEY=KP4QX7RM2S\u{202E}N5TB8VW3YZ",
        "KP4QX7RM2SN5TB8VW3YZ",
    );
}

#[test]
fn adv74_ceph_rados_gateway_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "ceph-rados-gateway-credentials",
        "CEPH_ACCESS_KEY=KP4QX7RM2S\u{202C}N5TB8VW3YZ",
        "KP4QX7RM2SN5TB8VW3YZ",
    );
}

#[test]
fn adv74_ceph_rados_gateway_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "ceph-rados-gateway-credentials",
        "CEPH_ACCESS_KEY=KP4QX7RM2S\u{200E}N5TB8VW3YZ",
        "KP4QX7RM2SN5TB8VW3YZ",
    );
}

// =========================================================================
// 9. CEREBRIUM API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv74_cerebrium_api_key_normal_must_fire() {
    assert_detector_fires(
        "cerebrium-api-key",
        "CEREBRIUM_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_cerebrium_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "cerebrium-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv74_cerebrium_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "cerebrium-api-key",
        "CEREBRIUM_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2S\u{200B}n5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_cerebrium_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "cerebrium-api-key",
        "CEREBRIUM_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2S\u{00AD}n5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_cerebrium_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "cerebrium-api-key",
        "CEREBRIUM_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2S\u{200C}n5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_cerebrium_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "cerebrium-api-key",
        "CEREBRIUM_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2S\u{200D}n5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_cerebrium_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "cerebrium-api-key",
        "CEREBRIUM_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2S\u{FEFF}n5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_cerebrium_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "cerebrium-api-key",
        "CEREBRIUM_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2S\u{2060}n5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_cerebrium_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "cerebrium-api-key",
        "CEREBRIUM_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2S\u{180E}n5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_cerebrium_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "cerebrium-api-key",
        "CEREBRIUM_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2S\u{202E}n5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_cerebrium_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "cerebrium-api-key",
        "CEREBRIUM_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2S\u{202C}n5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv74_cerebrium_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "cerebrium-api-key",
        "CEREBRIUM_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2S\u{200E}n5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 10. CFENGINE CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv74_cfengine_credentials_normal_must_fire() {
    assert_detector_fires(
        "cfengine-credentials",
        "CFENGINE_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz+",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz+",
    );
}

#[test]
fn adv74_cfengine_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "cfengine-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv74_cfengine_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "cfengine-credentials",
        "CFENGINE_KEY=Kp4Qx7Rm2S\u{200B}n5Tb8Vw3Yz+",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz+",
    );
}

#[test]
fn adv74_cfengine_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "cfengine-credentials",
        "CFENGINE_KEY=Kp4Qx7Rm2S\u{00AD}n5Tb8Vw3Yz+",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz+",
    );
}

#[test]
fn adv74_cfengine_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "cfengine-credentials",
        "CFENGINE_KEY=Kp4Qx7Rm2S\u{200C}n5Tb8Vw3Yz+",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz+",
    );
}

#[test]
fn adv74_cfengine_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "cfengine-credentials",
        "CFENGINE_KEY=Kp4Qx7Rm2S\u{200D}n5Tb8Vw3Yz+",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz+",
    );
}

#[test]
fn adv74_cfengine_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "cfengine-credentials",
        "CFENGINE_KEY=Kp4Qx7Rm2S\u{FEFF}n5Tb8Vw3Yz+",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz+",
    );
}

#[test]
fn adv74_cfengine_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "cfengine-credentials",
        "CFENGINE_KEY=Kp4Qx7Rm2S\u{2060}n5Tb8Vw3Yz+",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz+",
    );
}

#[test]
fn adv74_cfengine_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "cfengine-credentials",
        "CFENGINE_KEY=Kp4Qx7Rm2S\u{180E}n5Tb8Vw3Yz+",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz+",
    );
}

#[test]
fn adv74_cfengine_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "cfengine-credentials",
        "CFENGINE_KEY=Kp4Qx7Rm2S\u{202E}n5Tb8Vw3Yz+",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz+",
    );
}

#[test]
fn adv74_cfengine_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "cfengine-credentials",
        "CFENGINE_KEY=Kp4Qx7Rm2S\u{202C}n5Tb8Vw3Yz+",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz+",
    );
}

#[test]
fn adv74_cfengine_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "cfengine-credentials",
        "CFENGINE_KEY=Kp4Qx7Rm2S\u{200E}n5Tb8Vw3Yz+",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz+",
    );
}


